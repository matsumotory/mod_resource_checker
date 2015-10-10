/*
** mod_resource_checker - Measure resource between request and response
**
** Copyright (c) MATSUMOTO Ryosuke 2015 -
**
** Permission is hereby granted, free of charge, to any person obtaining
** a copy of this software and associated documentation files (the
** "Software"), to deal in the Software without restriction, including
** without limitation the rights to use, copy, modify, merge, publish,
** distribute, sublicense, and/or sell copies of the Software, and to
** permit persons to whom the Software is furnished to do so, subject to
** the following conditions:
**
** The above copyright notice and this permission notice shall be
** included in all copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
** EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
** MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
** IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
** CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
** TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
** SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
**
** [ MIT license: http://www.opensource.org/licenses/mit-license.php ]
*/

#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "http_log.h"
#include "apr_strings.h"
#include "util_time.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <libgen.h>
#include <time.h>
#include <json/json.h>

#if (AP_SERVER_MINORVERSION_NUMBER > 2)
#define __APACHE24__
#endif


#define MODULE_NAME "mod_resource_checker"
#define MODULE_VERSION "0.6.2"
#define ON 1
#define OFF 0

/* ------------------------ */
/* --- Macro Difinition --- */
/* ------------------------ */
#define INITIAL_VALUE 0
#define RESOURCE_CHECKER_DEFAULT_LOG_FILE "/tmp/mod_resource_checker.log"

/* ----------------------------------- */
/* --- Struct and Typed Definition --- */
/* ----------------------------------- */
typedef struct rusage_resouce_data {

  double cpu_utime;
  double cpu_stime;
  double shared_mem;

} RESOURCE_DATA;

typedef struct resource_checker_dir_conf {

  double cpu_utime;
  double cpu_stime;
  double shared_mem;
  char *utime_process_type;
  char *stime_process_type;
  char *mem_process_type;
  char *target_dir;
  int json_fmt;
  int check_status;
  int check_all;
  RESOURCE_DATA *pAnalysisResouceBefore;

} RESOURCE_CHECKER_D_CONF;

typedef struct client_access_data {

  char *access_uri;
  char *access_file;
  char *access_src_ip;
  char *access_dst_host;

} ACCESS_INFO;

typedef struct resource_checker_conf {

  char *log_filename;

} RESOURCE_CHECKER_CONF;

/* ----------------------------------- */
/* --- Grobal Variables Definition --- */
/* ----------------------------------- */
char mod_resource_checker_version[] = "mod_version 0.01";
int resource_checker_initialized = 0;

apr_file_t *mod_resource_checker_log_fp = NULL;

/* ------------------------- */
/* --- Module Definition --- */
/* ------------------------- */
module AP_MODULE_DECLARE_DATA resource_checker_module;

/* ------------------------------------------- */
/* --- Request Transaction Logging Routine --- */
/* ------------------------------------------- */
static double resource_checker_response_time(request_rec *r)
{
  apr_time_t duration = apr_time_now() - r->request_time;
  return (double)apr_time_sec(duration);
}

static const char *ap_mrb_string_check(apr_pool_t *p, const char *str)
{
  char *val;

  if (str == NULL) {
    val = apr_pstrdup(p, "null");
    return val;
  }

  return str;
}

static void _mod_resource_checker_logging_all(request_rec *r, RESOURCE_DATA *data, RESOURCE_CHECKER_D_CONF *conf,
                                              ACCESS_INFO *info, apr_pool_t *p)
{
  char log_time[APR_CTIME_LEN];
  char *mod_resource_checker_log_buf;
  json_object *log_obj, *result_obj;

  ap_recent_ctime(log_time, r->request_time);

  log_obj = json_object_new_object();
  result_obj = json_object_new_object();

  json_object_object_add(log_obj, "module", json_object_new_string(ap_mrb_string_check(r->pool, MODULE_NAME)));
  json_object_object_add(log_obj, "date", json_object_new_string(ap_mrb_string_check(r->pool, log_time)));
  json_object_object_add(log_obj, "type", json_object_new_string(ap_mrb_string_check(r->pool, "RCheckALL")));
  json_object_object_add(log_obj, "unit", NULL);
  json_object_object_add(log_obj, "location", json_object_new_string(ap_mrb_string_check(r->pool, conf->target_dir)));
  json_object_object_add(log_obj, "remote_ip",
                         json_object_new_string(ap_mrb_string_check(r->pool, info->access_src_ip)));
  json_object_object_add(log_obj, "filename", json_object_new_string(ap_mrb_string_check(r->pool, info->access_file)));
  json_object_object_add(log_obj, "scheme", json_object_new_string(ap_mrb_string_check(r->pool, ap_http_scheme(r))));
  json_object_object_add(log_obj, "method", json_object_new_string(ap_mrb_string_check(r->pool, r->method)));
  json_object_object_add(log_obj, "hostname", json_object_new_string(ap_mrb_string_check(r->pool, r->hostname)));
  json_object_object_add(log_obj, "uri", json_object_new_string(ap_mrb_string_check(r->pool, r->uri)));
  json_object_object_add(log_obj, "uid", json_object_new_int(r->finfo.user));
  json_object_object_add(log_obj, "size", json_object_new_int(r->finfo.size));
  json_object_object_add(log_obj, "content_length", json_object_new_int(r->clength));
  json_object_object_add(log_obj, "status", json_object_new_int(r->status));
  json_object_object_add(log_obj, "pid", json_object_new_int(getpid()));
  json_object_object_add(log_obj, "threshold", NULL);
  json_object_object_add(log_obj, "response_time", json_object_new_double(resource_checker_response_time(r)));

  json_object_object_add(result_obj, "RCheckUCPU", json_object_new_double(data->cpu_utime));
  json_object_object_add(result_obj, "RCheckSCPU", json_object_new_double(data->cpu_stime));
  json_object_object_add(result_obj, "RCheckMEM", json_object_new_double(data->shared_mem));
  json_object_object_add(log_obj, "result", result_obj);

  mod_resource_checker_log_buf = (char *)apr_psprintf(p, "%s\n", (char *)json_object_to_json_string(log_obj));

  apr_file_puts(mod_resource_checker_log_buf, mod_resource_checker_log_fp);
  apr_file_flush(mod_resource_checker_log_fp);

  json_object_put(result_obj);
  json_object_put(log_obj);
}

static void _mod_resource_checker_logging(request_rec *r, double resource_time, double threshold,
                                          char *process_type, RESOURCE_CHECKER_D_CONF *pDirConf,
                                          ACCESS_INFO *pAccessInfoData, const char *msg, const char *type,
                                          const char *unit, apr_pool_t *p)
{
  char log_time[APR_CTIME_LEN];
  char *mod_resource_checker_log_buf;
  json_object *log_obj = NULL;

  ap_recent_ctime(log_time, r->request_time);

  if (pDirConf->json_fmt == ON) {
    log_obj = json_object_new_object();
    json_object_object_add(log_obj, "module", json_object_new_string(ap_mrb_string_check(r->pool, msg)));
    json_object_object_add(log_obj, "date", json_object_new_string(ap_mrb_string_check(r->pool, log_time)));
    json_object_object_add(log_obj, "type", json_object_new_string(ap_mrb_string_check(r->pool, type)));
    json_object_object_add(log_obj, "unit", json_object_new_string(ap_mrb_string_check(r->pool, unit)));
    json_object_object_add(log_obj, "location",
                           json_object_new_string(ap_mrb_string_check(r->pool, pDirConf->target_dir)));
    json_object_object_add(log_obj, "remote_ip",
                           json_object_new_string(ap_mrb_string_check(r->pool, pAccessInfoData->access_src_ip)));
    json_object_object_add(log_obj, "filename",
                           json_object_new_string(ap_mrb_string_check(r->pool, pAccessInfoData->access_file)));
    json_object_object_add(log_obj, "scheme", json_object_new_string(ap_mrb_string_check(r->pool, ap_http_scheme(r))));
    json_object_object_add(log_obj, "method", json_object_new_string(ap_mrb_string_check(r->pool, r->method)));
    json_object_object_add(log_obj, "hostname", json_object_new_string(ap_mrb_string_check(r->pool, r->hostname)));
    json_object_object_add(log_obj, "uri", json_object_new_string(ap_mrb_string_check(r->pool, r->uri)));
    json_object_object_add(log_obj, "uid", json_object_new_int(r->finfo.user));
    json_object_object_add(log_obj, "size", json_object_new_int(r->finfo.size));
    json_object_object_add(log_obj, "content_length", json_object_new_int(r->clength));
    json_object_object_add(log_obj, "status", json_object_new_int(r->status));
    json_object_object_add(log_obj, "pid", json_object_new_int(getpid()));
    json_object_object_add(log_obj, "threshold", json_object_new_double(threshold));
    json_object_object_add(log_obj, "response_time", json_object_new_double(resource_checker_response_time(r)));
    json_object_object_add(log_obj, "result", json_object_new_double(resource_time));

    mod_resource_checker_log_buf = (char *)apr_psprintf(p, "%s\n", (char *)json_object_to_json_string(log_obj));
  } else {
    mod_resource_checker_log_buf = (char *)apr_psprintf(
        p,
        "[%s] pid=%d %s: [ %s(%s) = %.10f (%s) > threshold=(%.5f) ] config_dir=(%s) src_ip=(%s) access_file=(%s) "
        "request=(%s)\n",
        log_time, getpid(), msg, type, unit, resource_time, process_type, threshold, pDirConf->target_dir,
        pAccessInfoData->access_src_ip, pAccessInfoData->access_file, r->the_request);
  }

  apr_file_puts(mod_resource_checker_log_buf, mod_resource_checker_log_fp);
  apr_file_flush(mod_resource_checker_log_fp);

  if (log_obj != NULL)
    json_object_put(log_obj);
}

/* ------------------------------------------- */
/* --- Init Routine or ap_hook_post_config --- */
/* ------------------------------------------- */
static int resource_checker_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *server)
{
  RESOURCE_CHECKER_CONF *conf = ap_get_module_config(server->module_config, &resource_checker_module);

  if (*conf->log_filename == '|') {
    piped_log *pl;

    pl = ap_open_piped_log(p, conf->log_filename + 1);
    if (pl == NULL) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s ERROR %s: rchecker pipe log oepn failed: %s", MODULE_NAME,
                   __func__, conf->log_filename);

      return OK;
    }

    mod_resource_checker_log_fp = ap_piped_log_write_fd(pl);

  } else {
    if (apr_file_open(&mod_resource_checker_log_fp, conf->log_filename, APR_WRITE | APR_APPEND | APR_CREATE,
                      APR_OS_DEFAULT, p) != APR_SUCCESS) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s ERROR %s: rchecker log file oepn failed: %s", MODULE_NAME,
                   __func__, conf->log_filename);

      return OK;
    }
  }

  ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "%s/%s enabled: logging into %s", MODULE_NAME, MODULE_VERSION,
                conf->log_filename);

  resource_checker_initialized = 1;

  return OK;
}

/* ---------------------------- */
/* --- Create Dir Config --- */
/* ---------------------------- */
static void *resource_checker_create_dir_config(apr_pool_t *p, char *dir)
{
  RESOURCE_CHECKER_D_CONF *pDirConf = (RESOURCE_CHECKER_D_CONF *)apr_palloc(p, sizeof(RESOURCE_CHECKER_D_CONF));

  pDirConf->cpu_utime = INITIAL_VALUE;
  pDirConf->cpu_stime = INITIAL_VALUE;
  pDirConf->shared_mem = INITIAL_VALUE;
  pDirConf->json_fmt = ON;
  pDirConf->check_status = OFF;
  pDirConf->check_all = OFF;
  pDirConf->pAnalysisResouceBefore = (RESOURCE_DATA *)apr_pcalloc(p, sizeof(RESOURCE_DATA));
  ;

  if (dir == NULL) {
    pDirConf->target_dir = apr_pstrdup(p, "DocumentRoot");
  } else {
    pDirConf->target_dir = apr_pstrdup(p, dir);
  }

  return pDirConf;
}

static void *resource_checker_create_config(apr_pool_t *p, server_rec *s)
{
  RESOURCE_CHECKER_CONF *conf = (RESOURCE_CHECKER_CONF *)apr_pcalloc(p, sizeof(*conf));

  conf->log_filename = apr_pstrdup(p, RESOURCE_CHECKER_DEFAULT_LOG_FILE);

  return conf;
}

/* -------------------------------------------------------------------------------- */
/* --- Set ServerDirective in Struct Command_rec * Cmds (set_cpu_utime_resouce) --- */
/* -------------------------------------------------------------------------------- */
static const char *set_cpu_utime_resouce(cmd_parms *cmd, void *dir_config_fmt, char *arg1, char *arg2)
{
  RESOURCE_CHECKER_D_CONF *pDirConf;

  if (strcmp(arg2, "SELF") == -1 && strcmp(arg2, "CHILD") == -1 && strcmp(arg2, "THREAD") == -1 &&
      strcmp(arg2, "ALL") == -1)
    return "RCheckUCPU: arg2 is SELF or CHILD or or THREAD or ALL!";

  if (atof(arg1) <= 0)
    return "RCheckUCPU: arg1 must be only a number( > 0 )!";

  pDirConf = (RESOURCE_CHECKER_D_CONF *)dir_config_fmt;
  pDirConf->cpu_utime = atof(arg1);
  pDirConf->utime_process_type = apr_pstrdup(cmd->pool, arg2);

  return NULL;
}

/* -------------------------------------------------------------------------------- */
/* --- Set ServerDirective in Struct Command_rec * Cmds (set_cpu_stime_resouce) --- */
/* -------------------------------------------------------------------------------- */
static const char *set_cpu_stime_resouce(cmd_parms *cmd, void *dir_config_fmt, char *arg1, char *arg2)
{
  RESOURCE_CHECKER_D_CONF *pDirConf;

  if (strcmp(arg2, "SELF") == -1 && strcmp(arg2, "CHILD") == -1 && strcmp(arg2, "THREAD") == -1 &&
      strcmp(arg2, "ALL") == -1)
    return "RCheckSCPU: arg2 is SELF or CHILD or THREAD or ALL!";

  if (atof(arg1) <= 0)
    return "RCheckSCPU: arg1 must be only a number( > 0 )!";

  pDirConf = (RESOURCE_CHECKER_D_CONF *)dir_config_fmt;
  pDirConf->cpu_stime = atof(arg1);
  pDirConf->stime_process_type = apr_pstrdup(cmd->pool, arg2);

  return NULL;
}

/* -------------------------------------------------------------------------------- */
/* --- Set ServerDirective in Struct Command_rec * Cmds (set_shared_mem_resouce) --- */
/* -------------------------------------------------------------------------------- */
static const char *set_shared_mem_resouce(cmd_parms *cmd, void *dir_config_fmt, char *arg1, char *arg2)
{
  RESOURCE_CHECKER_D_CONF *pDirConf;

  if (strcmp(arg2, "SELF") == -1 && strcmp(arg2, "CHILD") == -1 && strcmp(arg2, "THREAD") == -1 &&
      strcmp(arg2, "ALL") == -1)
    return "RCheckMEM: arg2 is SELF or CHILD or THREAD or ALL!";

  if (atof(arg1) <= 0)
    return "RCheckMEM: arg1 must be only a number( > 0 )!";

  pDirConf = (RESOURCE_CHECKER_D_CONF *)dir_config_fmt;
  pDirConf->shared_mem = atof(arg1);
  pDirConf->mem_process_type = apr_pstrdup(cmd->pool, arg2);

  return NULL;
}

static const char *set_json_fmt_resource(cmd_parms *cmd, void *dir_config_fmt, int enable)
{
  RESOURCE_CHECKER_D_CONF *pDirConf = (RESOURCE_CHECKER_D_CONF *)dir_config_fmt;
  pDirConf->json_fmt = enable;
  return NULL;
}

static const char *set_status_resource(cmd_parms *cmd, void *dir_config_fmt, int enable)
{
  RESOURCE_CHECKER_D_CONF *pDirConf = (RESOURCE_CHECKER_D_CONF *)dir_config_fmt;
  pDirConf->check_status = enable;
  return NULL;
}

static const char *set_all_resource(cmd_parms *cmd, void *dir_config_fmt, int enable)
{
  RESOURCE_CHECKER_D_CONF *pDirConf = (RESOURCE_CHECKER_D_CONF *)dir_config_fmt;
  pDirConf->check_all = enable;
  return NULL;
}

static const char *set_rcheck_logname(cmd_parms *cmd, void *dir_config_fmt, const char *log_filename)
{
  RESOURCE_CHECKER_CONF *conf = ap_get_module_config(cmd->server->module_config, &resource_checker_module);
  conf->log_filename = apr_pstrdup(cmd->pool, log_filename);
  return NULL;
}

/* --------------------------- */
/* --- get rutime (doubel) --- */
/* --------------------------- */
static double get_time_from_rutime(time_t sec, suseconds_t usec)
{
  return sec + (double)usec * 1e-6;
}

/* ----------------------------- */
/* --- get process resources --- */
/* ----------------------------- */
static double _get_rusage_resource(apr_pool_t *p, char *type, char *member)
{
  struct rusage *resources;
  struct rusage *resources_s;
  struct rusage *resources_c;

  RESOURCE_DATA *pAnalysisResouce;
  pAnalysisResouce = (RESOURCE_DATA *)apr_pcalloc(p, sizeof(RESOURCE_DATA));
  resources = (struct rusage *)apr_pcalloc(p, sizeof(struct rusage));

  if (strcmp(type, "SELF") == 0) {
    if (getrusage(RUSAGE_SELF, resources) == -1) {
      pAnalysisResouce->cpu_utime = INITIAL_VALUE;
      pAnalysisResouce->cpu_stime = INITIAL_VALUE;
      return -1;
    }
  } else if (strcmp(type, "CHILD") == 0) {
    if (getrusage(RUSAGE_CHILDREN, resources) == -1) {
      pAnalysisResouce->cpu_utime = INITIAL_VALUE;
      pAnalysisResouce->cpu_stime = INITIAL_VALUE;
      return -1;
    }
  } else if (strcmp(type, "THREAD") == 0) {
    if (getrusage(RUSAGE_THREAD, resources) == -1) {
      pAnalysisResouce->cpu_utime = INITIAL_VALUE;
      pAnalysisResouce->cpu_stime = INITIAL_VALUE;
      return -1;
    }
  } else if (strcmp(type, "ALL") == 0) {
    resources_s = (struct rusage *)apr_pcalloc(p, sizeof(struct rusage));
    resources_c = (struct rusage *)apr_pcalloc(p, sizeof(struct rusage));
    if (getrusage(RUSAGE_SELF, resources_s) == -1) {
      pAnalysisResouce->cpu_utime = INITIAL_VALUE;
      pAnalysisResouce->cpu_stime = INITIAL_VALUE;
      return -1;
    }
    if (getrusage(RUSAGE_CHILDREN, resources_c) == -1) {
      pAnalysisResouce->cpu_utime = INITIAL_VALUE;
      pAnalysisResouce->cpu_stime = INITIAL_VALUE;
      return -1;
    }
    resources->ru_utime.tv_sec = resources_s->ru_utime.tv_sec + resources_c->ru_utime.tv_sec;
    resources->ru_utime.tv_usec = resources_s->ru_utime.tv_usec + resources_c->ru_utime.tv_usec;
    resources->ru_stime.tv_sec = resources_s->ru_stime.tv_sec + resources_c->ru_stime.tv_sec;
    resources->ru_stime.tv_usec = resources_s->ru_stime.tv_usec + resources_c->ru_stime.tv_usec;
    resources->ru_minflt = resources_s->ru_minflt + resources_c->ru_minflt;
  }

  pAnalysisResouce->cpu_utime = get_time_from_rutime(resources->ru_utime.tv_sec, resources->ru_utime.tv_usec);
  pAnalysisResouce->cpu_stime = get_time_from_rutime(resources->ru_stime.tv_sec, resources->ru_stime.tv_usec);
  pAnalysisResouce->shared_mem = (((double)resources->ru_minflt * (double)getpagesize() / 1024 / 1024));

  // unexpected value; resource is negative number
  if (pAnalysisResouce->cpu_utime < 0) {
    pAnalysisResouce->cpu_utime = 0;
  }
  if (pAnalysisResouce->cpu_stime < 0) {
    pAnalysisResouce->cpu_stime = 0;
  }
  if (pAnalysisResouce->shared_mem < 0) {
    pAnalysisResouce->shared_mem = 0;
  }

  if (strcmp(member, "cpu_utime") == 0) {
    return pAnalysisResouce->cpu_utime;
  } else if (strcmp(member, "cpu_stime") == 0) {
    return pAnalysisResouce->cpu_stime;
  } else if (strcmp(member, "shared_mem") == 0) {
    return pAnalysisResouce->shared_mem;
  }

  return -1;
}

/* ----------------------------------------------- */
/* --- Access Checker (ap_hook_access_checker) --- */
/* ----------------------------------------------- */
static int before_resource_checker(request_rec *r)
{
  RESOURCE_CHECKER_D_CONF *pDirConf =
      (RESOURCE_CHECKER_D_CONF *)ap_get_module_config(r->per_dir_config, &resource_checker_module);
  RESOURCE_DATA *pAnalysisResouceBefore = pDirConf->pAnalysisResouceBefore;

  if (pDirConf->cpu_utime == INITIAL_VALUE && pDirConf->cpu_stime == INITIAL_VALUE &&
      pDirConf->shared_mem == INITIAL_VALUE && pDirConf->check_all == OFF)
    return DECLINED;

  int match;
  struct stat sb;

  if (resource_checker_initialized == 0) {
    return OK;
  }

  if (r->main && (stat(r->filename, &sb) == -1) && errno == ENOENT) {
    return OK;
  }

  match = 0;
  pAnalysisResouceBefore->cpu_utime = INITIAL_VALUE;
  pAnalysisResouceBefore->cpu_stime = INITIAL_VALUE;
  pAnalysisResouceBefore->shared_mem = INITIAL_VALUE;

  if (pDirConf->cpu_utime > INITIAL_VALUE || pDirConf->check_all == ON) {
    match = 1;
    if (pDirConf->check_all == ON)
      pAnalysisResouceBefore->cpu_utime = _get_rusage_resource(r->pool, "ALL", "cpu_utime");
    else
      pAnalysisResouceBefore->cpu_utime = _get_rusage_resource(r->pool, pDirConf->utime_process_type, "cpu_utime");
  }

  if (pDirConf->cpu_stime > INITIAL_VALUE || pDirConf->check_all == ON) {
    match = 1;
    if (pDirConf->check_all == ON)
      pAnalysisResouceBefore->cpu_stime = _get_rusage_resource(r->pool, "ALL", "cpu_stime");
    else
      pAnalysisResouceBefore->cpu_stime = _get_rusage_resource(r->pool, pDirConf->stime_process_type, "cpu_stime");
  }

  if (pDirConf->shared_mem > INITIAL_VALUE || pDirConf->check_all == ON) {
    match = 1;
    if (pDirConf->check_all == ON)
      pAnalysisResouceBefore->shared_mem = _get_rusage_resource(r->pool, "ALL", "shared_mem");
    else
      pAnalysisResouceBefore->shared_mem = _get_rusage_resource(r->pool, pDirConf->mem_process_type, "shared_mem");
  }

  if (match == 0) {
    return OK;
  }

  return OK;
}

/* ------------------------------------------------- */
/* --- log transantion (ap_hook_log_transaction) --- */
/* ------------------------------------------------- */
static int after_resource_checker(request_rec *r)
{
  RESOURCE_CHECKER_D_CONF *pDirConf =
      (RESOURCE_CHECKER_D_CONF *)ap_get_module_config(r->per_dir_config, &resource_checker_module);
  RESOURCE_DATA *pAnalysisResouceBefore = pDirConf->pAnalysisResouceBefore;

  if (pDirConf->cpu_utime == INITIAL_VALUE && pDirConf->cpu_stime == INITIAL_VALUE &&
      pDirConf->shared_mem == INITIAL_VALUE && pDirConf->check_status == OFF && pDirConf->check_all == OFF)
    return DECLINED;

  int match;
  struct stat sb;
  RESOURCE_DATA *pAnalysisResouceAfter;
  pAnalysisResouceAfter = (RESOURCE_DATA *)apr_pcalloc(r->pool, sizeof(RESOURCE_DATA));
  RESOURCE_DATA *pAnalysisResouceNow;
  pAnalysisResouceNow = (RESOURCE_DATA *)apr_pcalloc(r->pool, sizeof(RESOURCE_DATA));

  ACCESS_INFO *pAccessInfoData;
  pAccessInfoData = (ACCESS_INFO *)apr_pcalloc(r->pool, sizeof(ACCESS_INFO));

  if (resource_checker_initialized == 0) {
    return OK;
  }

  if (r->main && (stat(r->filename, &sb) == -1) && errno == ENOENT) {
    return OK;
  }

  pAccessInfoData->access_uri = r->uri;
  pAccessInfoData->access_file = r->filename;
#ifdef __APACHE24__
  pAccessInfoData->access_src_ip = r->connection->client_ip;
#else
  pAccessInfoData->access_src_ip = r->connection->remote_ip;
#endif
  pAccessInfoData->access_dst_host = r->server->server_hostname;

  if (pDirConf->check_status == ON) {
    _mod_resource_checker_logging(r, 0, 0, NULL, pDirConf, pAccessInfoData, MODULE_NAME, "RCheckSTATUS", NULL, r->pool);
  }

  // threashould check
  if (pAnalysisResouceBefore == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "%s NOTICE %s: Can not check resource of the request: file = %s",
                  MODULE_NAME, __func__, r->filename);
    return DECLINED;
  }

  match = 0;
  pAnalysisResouceAfter->cpu_utime = INITIAL_VALUE;
  pAnalysisResouceAfter->cpu_stime = INITIAL_VALUE;
  pAnalysisResouceAfter->shared_mem = INITIAL_VALUE;

  if (pDirConf->cpu_utime > INITIAL_VALUE || pDirConf->check_all == ON) {
    match = 1;
    if (pDirConf->check_all == ON)
      pAnalysisResouceAfter->cpu_utime = _get_rusage_resource(r->pool, "ALL", "cpu_utime");
    else
      pAnalysisResouceAfter->cpu_utime = _get_rusage_resource(r->pool, pDirConf->utime_process_type, "cpu_utime");
  }

  if (pDirConf->cpu_stime > INITIAL_VALUE || pDirConf->check_all == ON) {
    match = 1;
    if (pDirConf->check_all == ON)
      pAnalysisResouceAfter->cpu_stime = _get_rusage_resource(r->pool, "ALL", "cpu_stime");
    else
      pAnalysisResouceAfter->cpu_stime = _get_rusage_resource(r->pool, pDirConf->stime_process_type, "cpu_stime");
  }

  if (pDirConf->shared_mem > INITIAL_VALUE || pDirConf->check_all == ON) {
    match = 1;
    if (pDirConf->check_all == ON)
      pAnalysisResouceAfter->shared_mem = _get_rusage_resource(r->pool, "ALL", "shared_mem");
    else
      pAnalysisResouceAfter->shared_mem = _get_rusage_resource(r->pool, pDirConf->mem_process_type, "shared_mem");
  }

  if (match == 0) {
    return OK;
  }

  pAnalysisResouceNow->cpu_utime = pAnalysisResouceAfter->cpu_utime - pAnalysisResouceBefore->cpu_utime;
  pAnalysisResouceNow->cpu_stime = pAnalysisResouceAfter->cpu_stime - pAnalysisResouceBefore->cpu_stime;
  pAnalysisResouceNow->shared_mem = pAnalysisResouceAfter->shared_mem - pAnalysisResouceBefore->shared_mem;

  // unexpected value; resource is negative number
  if (pAnalysisResouceNow->cpu_utime < 0) {
    pAnalysisResouceNow->cpu_utime = 0;
  }
  if (pAnalysisResouceNow->cpu_stime < 0) {
    pAnalysisResouceNow->cpu_stime = 0;
  }
  if (pAnalysisResouceNow->shared_mem < 0) {
    pAnalysisResouceNow->shared_mem = 0;
  }

  if (pDirConf->cpu_utime > INITIAL_VALUE && pAnalysisResouceNow->cpu_utime >= pDirConf->cpu_utime) {
    _mod_resource_checker_logging(r, pAnalysisResouceNow->cpu_utime, pDirConf->cpu_utime, pDirConf->utime_process_type,
                                  pDirConf, pAccessInfoData, MODULE_NAME, "RCheckUCPU", "sec", r->pool);
  }

  if (pDirConf->cpu_stime > INITIAL_VALUE && pAnalysisResouceNow->cpu_stime >= pDirConf->cpu_stime) {
    _mod_resource_checker_logging(r, pAnalysisResouceNow->cpu_stime, pDirConf->cpu_stime, pDirConf->stime_process_type,
                                  pDirConf, pAccessInfoData, MODULE_NAME, "RCheckSCPU", "sec", r->pool);
  }

  if (pDirConf->shared_mem > INITIAL_VALUE && pAnalysisResouceNow->shared_mem >= pDirConf->shared_mem) {
    _mod_resource_checker_logging(r, pAnalysisResouceNow->shared_mem, pDirConf->shared_mem, pDirConf->mem_process_type,
                                  pDirConf, pAccessInfoData, MODULE_NAME, "RCheckMEM", "MiB", r->pool);
  }

  if (pDirConf->check_all == ON && pDirConf->json_fmt == ON) {
    _mod_resource_checker_logging_all(r, pAnalysisResouceNow, pDirConf, pAccessInfoData, r->pool);
  }

  return OK;
}

/* ------------------- */
/* --- Command_rec --- */
/* ------------------- */
static const command_rec resource_checker_cmds[] = {
    AP_INIT_TAKE2("RCheckUCPU", (void *)set_cpu_utime_resouce, NULL, RSRC_CONF | ACCESS_CONF,
                  "Set Resource Checker User CPU Time."),
    AP_INIT_TAKE2("RCheckSCPU", (void *)set_cpu_stime_resouce, NULL, RSRC_CONF | ACCESS_CONF,
                  "Set Resource Checker System CPU Time."),
    AP_INIT_TAKE2("RCheckMEM", (void *)set_shared_mem_resouce, NULL, RSRC_CONF | ACCESS_CONF,
                  "Set Resource Checker Process Memory."),
    AP_INIT_FLAG("RCheckJSONFormat", set_json_fmt_resource, NULL, RSRC_CONF | ACCESS_CONF, "Output by JSON Format."),
    AP_INIT_FLAG("RCheckSTATUS", set_status_resource, NULL, RSRC_CONF | ACCESS_CONF, "Output STATUS log only."),
    AP_INIT_FLAG("RCheckALL", set_all_resource, NULL, RSRC_CONF | ACCESS_CONF, "Output all resource log on one line."),
    AP_INIT_TAKE1("RCheckLogPath", set_rcheck_logname, NULL, RSRC_CONF | ACCESS_CONF, "RCheck log name."),
    {NULL}};

/* -------------- */
/* --- Module --- */
/* -------------- */
static void resource_checker_register_hooks(apr_pool_t *p)
{
  ap_hook_post_config((void *)resource_checker_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_access_checker(before_resource_checker, NULL, NULL, APR_HOOK_LAST);
  ap_hook_log_transaction(after_resource_checker, NULL, NULL, APR_HOOK_LAST);
}

#ifdef __APACHE24__
AP_DECLARE_MODULE(resource_checker) = {
#else
module AP_MODULE_DECLARE_DATA resource_checker_module = {
#endif
    STANDARD20_MODULE_STUFF, (void *)resource_checker_create_dir_config, /* create per-dir    config structures */
    NULL,                                                                /* merge  per-dir    config structures */
    (void *)resource_checker_create_config,                              /* create per-server config structures */
    NULL,                                                                /* merge  per-server config structures */
    resource_checker_cmds,                                               /* table of config file commands       */
    resource_checker_register_hooks                                      /* register hooks                      */
};
