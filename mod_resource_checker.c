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
#define MODULE_VERSION "0.8.4"
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
typedef struct mod_rc_rusage_st {

  double cpu_utime;
  double cpu_stime;
  double shared_mem;

} mod_rc_rusage;

typedef struct mod_rc_dir_conf_st {

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
  mod_rc_rusage *before_resources;

} mod_rc_dir_conf;

typedef struct mod_rc_client_data_st {

  char *access_uri;
  char *access_file;
  char *access_src_ip;
  char *access_dst_host;

} mod_rc_client_data;

typedef struct mod_rc_conf_st {

  char *log_filename;
  char *real_server_name;

} mod_rc_conf;

/* ----------------------------------- */
/* --- Grobal Variables Definition --- */
/* ----------------------------------- */
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

static json_object *mod_rc_json_object_new_string(const char *str)
{
  if (str == NULL)
    return NULL;

  return json_object_new_string(str);
}

static void _mod_resource_checker_logging_all(request_rec *r, mod_rc_rusage *data, mod_rc_dir_conf *conf, mod_rc_conf *sconf,
                                              mod_rc_client_data *info, apr_pool_t *p)
{
  char log_time[APR_CTIME_LEN];
  char *mod_resource_checker_log_buf;
  json_object *log_obj, *result_obj;

  ap_recent_ctime(log_time, r->request_time);

  log_obj = json_object_new_object();
  result_obj = json_object_new_object();

  json_object_object_add(log_obj, "module", mod_rc_json_object_new_string(MODULE_NAME));
  json_object_object_add(log_obj, "date", mod_rc_json_object_new_string(log_time));
  json_object_object_add(log_obj, "type", mod_rc_json_object_new_string("RCheckALL"));
  json_object_object_add(log_obj, "unit", NULL);
  json_object_object_add(log_obj, "location", mod_rc_json_object_new_string(conf->target_dir));
  json_object_object_add(log_obj, "remote_ip", mod_rc_json_object_new_string(info->access_src_ip));
  json_object_object_add(log_obj, "filename", mod_rc_json_object_new_string(info->access_file));
  json_object_object_add(log_obj, "scheme", mod_rc_json_object_new_string(ap_http_scheme(r)));
  json_object_object_add(log_obj, "method", mod_rc_json_object_new_string(r->method));
  json_object_object_add(log_obj, "hostname", mod_rc_json_object_new_string(r->server->server_hostname));
  json_object_object_add(log_obj, "server_ip", mod_rc_json_object_new_string(r->connection->local_ip));
  json_object_object_add(log_obj, "uri", mod_rc_json_object_new_string(r->uri));
  json_object_object_add(log_obj, "handler", mod_rc_json_object_new_string(r->handler));
  json_object_object_add(log_obj, "real_server_name", mod_rc_json_object_new_string(sconf->real_server_name));

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

static void _mod_resource_checker_logging(request_rec *r, double resource_time, double threshold, char *process_type,
                                          mod_rc_dir_conf *dconf, mod_rc_client_data *cdata, const char *msg,
                                          const char *type, const char *unit, apr_pool_t *p)
{
  char log_time[APR_CTIME_LEN];
  char *mod_resource_checker_log_buf;
  json_object *log_obj = NULL;

  ap_recent_ctime(log_time, r->request_time);

  if (dconf->json_fmt == ON) {
    log_obj = json_object_new_object();
    json_object_object_add(log_obj, "module", mod_rc_json_object_new_string(msg));
    json_object_object_add(log_obj, "date", mod_rc_json_object_new_string(log_time));
    json_object_object_add(log_obj, "type", mod_rc_json_object_new_string(type));
    json_object_object_add(log_obj, "unit", mod_rc_json_object_new_string(unit));
    json_object_object_add(log_obj, "location", mod_rc_json_object_new_string(dconf->target_dir));
    json_object_object_add(log_obj, "remote_ip", mod_rc_json_object_new_string(cdata->access_src_ip));
    json_object_object_add(log_obj, "filename", mod_rc_json_object_new_string(cdata->access_file));
    json_object_object_add(log_obj, "scheme", mod_rc_json_object_new_string(ap_http_scheme(r)));
    json_object_object_add(log_obj, "method", mod_rc_json_object_new_string(r->method));
    json_object_object_add(log_obj, "hostname", mod_rc_json_object_new_string(r->hostname));
    json_object_object_add(log_obj, "uri", mod_rc_json_object_new_string(r->uri));
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
        p, "[%s] pid=%d %s: [ %s(%s) = %.10f (%s) > threshold=(%.5f) ] config_dir=(%s) src_ip=(%s) access_file=(%s) "
           "request=(%s)\n",
        log_time, getpid(), msg, type, unit, resource_time, process_type, threshold, dconf->target_dir,
        cdata->access_src_ip, cdata->access_file, r->the_request);
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
  mod_rc_conf *conf = ap_get_module_config(server->module_config, &resource_checker_module);
  void *data;
  const char *userdata_key = "resource_checker_init";

  apr_pool_userdata_get(&data, userdata_key, server->process->pool);

  if (!data) {
    apr_pool_userdata_set((const void *)1, userdata_key, apr_pool_cleanup_null, server->process->pool);
    return OK;
  }

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
  mod_rc_dir_conf *dconf = (mod_rc_dir_conf *)apr_palloc(p, sizeof(mod_rc_dir_conf));

  dconf->cpu_utime = INITIAL_VALUE;
  dconf->cpu_stime = INITIAL_VALUE;
  dconf->shared_mem = INITIAL_VALUE;
  dconf->json_fmt = ON;
  dconf->check_status = OFF;
  dconf->check_all = OFF;
  dconf->before_resources = (mod_rc_rusage *)apr_pcalloc(p, sizeof(mod_rc_rusage));
  ;

  if (dir == NULL) {
    dconf->target_dir = apr_pstrdup(p, "DocumentRoot");
  } else {
    dconf->target_dir = apr_pstrdup(p, dir);
  }

  return dconf;
}

static void *resource_checker_create_config(apr_pool_t *p, server_rec *s)
{
  mod_rc_conf *conf = (mod_rc_conf *)apr_pcalloc(p, sizeof(*conf));

  conf->log_filename = apr_pstrdup(p, RESOURCE_CHECKER_DEFAULT_LOG_FILE);
  conf->real_server_name = NULL;

  return conf;
}

/* -------------------------------------------------------------------------------- */
/* --- Set ServerDirective in Struct Command_rec * Cmds (set_cpu_utime_resouce) --- */
/* -------------------------------------------------------------------------------- */
static const char *set_cpu_utime_resouce(cmd_parms *cmd, void *dir_config_fmt, char *arg1, char *arg2)
{
  mod_rc_dir_conf *dconf;

  if (strcmp(arg2, "SELF") == -1 && strcmp(arg2, "CHILD") == -1 && strcmp(arg2, "THREAD") == -1 &&
      strcmp(arg2, "ALL") == -1)
    return "RCheckUCPU: arg2 is SELF or CHILD or or THREAD or ALL!";

  if (atof(arg1) <= 0)
    return "RCheckUCPU: arg1 must be only a number( > 0 )!";

  dconf = (mod_rc_dir_conf *)dir_config_fmt;
  dconf->cpu_utime = atof(arg1);
  dconf->utime_process_type = apr_pstrdup(cmd->pool, arg2);

  return NULL;
}

/* -------------------------------------------------------------------------------- */
/* --- Set ServerDirective in Struct Command_rec * Cmds (set_cpu_stime_resouce) --- */
/* -------------------------------------------------------------------------------- */
static const char *set_cpu_stime_resouce(cmd_parms *cmd, void *dir_config_fmt, char *arg1, char *arg2)
{
  mod_rc_dir_conf *dconf;

  if (strcmp(arg2, "SELF") == -1 && strcmp(arg2, "CHILD") == -1 && strcmp(arg2, "THREAD") == -1 &&
      strcmp(arg2, "ALL") == -1)
    return "RCheckSCPU: arg2 is SELF or CHILD or THREAD or ALL!";

  if (atof(arg1) <= 0)
    return "RCheckSCPU: arg1 must be only a number( > 0 )!";

  dconf = (mod_rc_dir_conf *)dir_config_fmt;
  dconf->cpu_stime = atof(arg1);
  dconf->stime_process_type = apr_pstrdup(cmd->pool, arg2);

  return NULL;
}

/* -------------------------------------------------------------------------------- */
/* --- Set ServerDirective in Struct Command_rec * Cmds (set_shared_mem_resouce) --- */
/* -------------------------------------------------------------------------------- */
static const char *set_shared_mem_resouce(cmd_parms *cmd, void *dir_config_fmt, char *arg1, char *arg2)
{
  mod_rc_dir_conf *dconf;

  if (strcmp(arg2, "SELF") == -1 && strcmp(arg2, "CHILD") == -1 && strcmp(arg2, "THREAD") == -1 &&
      strcmp(arg2, "ALL") == -1)
    return "RCheckMEM: arg2 is SELF or CHILD or THREAD or ALL!";

  if (atof(arg1) <= 0)
    return "RCheckMEM: arg1 must be only a number( > 0 )!";

  dconf = (mod_rc_dir_conf *)dir_config_fmt;
  dconf->shared_mem = atof(arg1);
  dconf->mem_process_type = apr_pstrdup(cmd->pool, arg2);

  return NULL;
}

static const char *set_json_fmt_resource(cmd_parms *cmd, void *dir_config_fmt, int enable)
{
  mod_rc_dir_conf *dconf = (mod_rc_dir_conf *)dir_config_fmt;
  dconf->json_fmt = enable;
  return NULL;
}

static const char *set_status_resource(cmd_parms *cmd, void *dir_config_fmt, int enable)
{
  mod_rc_dir_conf *dconf = (mod_rc_dir_conf *)dir_config_fmt;
  dconf->check_status = enable;
  return NULL;
}

static const char *set_all_resource(cmd_parms *cmd, void *dir_config_fmt, int enable)
{
  mod_rc_dir_conf *dconf = (mod_rc_dir_conf *)dir_config_fmt;
  dconf->check_all = enable;
  return NULL;
}

static const char *set_rcheck_logname(cmd_parms *cmd, void *dir_config_fmt, const char *log_filename)
{
  mod_rc_conf *conf = ap_get_module_config(cmd->server->module_config, &resource_checker_module);
  conf->log_filename = apr_pstrdup(cmd->pool, log_filename);
  return NULL;
}

static const char *set_real_server_name(cmd_parms *cmd, void *dir_config_fmt, const char *name)
{
  mod_rc_conf *conf = ap_get_module_config(cmd->server->module_config, &resource_checker_module);
  conf->real_server_name = apr_pstrdup(cmd->pool, name);
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

  mod_rc_rusage *rc_data;
  rc_data = (mod_rc_rusage *)apr_pcalloc(p, sizeof(mod_rc_rusage));
  resources = (struct rusage *)apr_pcalloc(p, sizeof(struct rusage));

  if (strcmp(type, "SELF") == 0) {
    if (getrusage(RUSAGE_SELF, resources) == -1) {
      rc_data->cpu_utime = INITIAL_VALUE;
      rc_data->cpu_stime = INITIAL_VALUE;
      return -1;
    }
  } else if (strcmp(type, "CHILD") == 0) {
    if (getrusage(RUSAGE_CHILDREN, resources) == -1) {
      rc_data->cpu_utime = INITIAL_VALUE;
      rc_data->cpu_stime = INITIAL_VALUE;
      return -1;
    }
  } else if (strcmp(type, "THREAD") == 0) {
    if (getrusage(RUSAGE_THREAD, resources) == -1) {
      rc_data->cpu_utime = INITIAL_VALUE;
      rc_data->cpu_stime = INITIAL_VALUE;
      return -1;
    }
  } else if (strcmp(type, "ALL") == 0) {
    resources_s = (struct rusage *)apr_pcalloc(p, sizeof(struct rusage));
    resources_c = (struct rusage *)apr_pcalloc(p, sizeof(struct rusage));
    if (getrusage(RUSAGE_SELF, resources_s) == -1) {
      rc_data->cpu_utime = INITIAL_VALUE;
      rc_data->cpu_stime = INITIAL_VALUE;
      return -1;
    }
    if (getrusage(RUSAGE_CHILDREN, resources_c) == -1) {
      rc_data->cpu_utime = INITIAL_VALUE;
      rc_data->cpu_stime = INITIAL_VALUE;
      return -1;
    }
    resources->ru_utime.tv_sec = resources_s->ru_utime.tv_sec + resources_c->ru_utime.tv_sec;
    resources->ru_utime.tv_usec = resources_s->ru_utime.tv_usec + resources_c->ru_utime.tv_usec;
    resources->ru_stime.tv_sec = resources_s->ru_stime.tv_sec + resources_c->ru_stime.tv_sec;
    resources->ru_stime.tv_usec = resources_s->ru_stime.tv_usec + resources_c->ru_stime.tv_usec;
    resources->ru_minflt = resources_s->ru_minflt + resources_c->ru_minflt;
  }

  rc_data->cpu_utime = get_time_from_rutime(resources->ru_utime.tv_sec, resources->ru_utime.tv_usec);
  rc_data->cpu_stime = get_time_from_rutime(resources->ru_stime.tv_sec, resources->ru_stime.tv_usec);
  rc_data->shared_mem = (((double)resources->ru_minflt * (double)getpagesize() / 1024 / 1024));

  // unexpected value; resource is negative number
  if (rc_data->cpu_utime < 0) {
    rc_data->cpu_utime = 0;
  }
  if (rc_data->cpu_stime < 0) {
    rc_data->cpu_stime = 0;
  }
  if (rc_data->shared_mem < 0) {
    rc_data->shared_mem = 0;
  }

  if (strcmp(member, "cpu_utime") == 0) {
    return rc_data->cpu_utime;
  } else if (strcmp(member, "cpu_stime") == 0) {
    return rc_data->cpu_stime;
  } else if (strcmp(member, "shared_mem") == 0) {
    return rc_data->shared_mem;
  }

  return -1;
}

/* ----------------------------------------------- */
/* --- Access Checker (ap_hook_access_checker) --- */
/* ----------------------------------------------- */
static int before_resource_checker(request_rec *r)
{
  mod_rc_dir_conf *dconf = (mod_rc_dir_conf *)ap_get_module_config(r->per_dir_config, &resource_checker_module);
  mod_rc_rusage *before_resources = dconf->before_resources;

  if (dconf->cpu_utime == INITIAL_VALUE && dconf->cpu_stime == INITIAL_VALUE && dconf->shared_mem == INITIAL_VALUE &&
      dconf->check_all == OFF)
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
  before_resources->cpu_utime = INITIAL_VALUE;
  before_resources->cpu_stime = INITIAL_VALUE;
  before_resources->shared_mem = INITIAL_VALUE;

  if (dconf->cpu_utime > INITIAL_VALUE || dconf->check_all == ON) {
    match = 1;
    if (dconf->check_all == ON)
      before_resources->cpu_utime = _get_rusage_resource(r->pool, "ALL", "cpu_utime");
    else
      before_resources->cpu_utime = _get_rusage_resource(r->pool, dconf->utime_process_type, "cpu_utime");
  }

  if (dconf->cpu_stime > INITIAL_VALUE || dconf->check_all == ON) {
    match = 1;
    if (dconf->check_all == ON)
      before_resources->cpu_stime = _get_rusage_resource(r->pool, "ALL", "cpu_stime");
    else
      before_resources->cpu_stime = _get_rusage_resource(r->pool, dconf->stime_process_type, "cpu_stime");
  }

  if (dconf->shared_mem > INITIAL_VALUE || dconf->check_all == ON) {
    match = 1;
    if (dconf->check_all == ON)
      before_resources->shared_mem = _get_rusage_resource(r->pool, "ALL", "shared_mem");
    else
      before_resources->shared_mem = _get_rusage_resource(r->pool, dconf->mem_process_type, "shared_mem");
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
  mod_rc_dir_conf *dconf = (mod_rc_dir_conf *)ap_get_module_config(r->per_dir_config, &resource_checker_module);
  mod_rc_conf *sconf = (mod_rc_conf *)ap_get_module_config(r->server->module_config, &resource_checker_module);
  mod_rc_rusage *before_resources = dconf->before_resources;

  if (dconf->cpu_utime == INITIAL_VALUE && dconf->cpu_stime == INITIAL_VALUE && dconf->shared_mem == INITIAL_VALUE &&
      dconf->check_status == OFF && dconf->check_all == OFF)
    return DECLINED;

  int match;
  struct stat sb;
  mod_rc_rusage *after_resources;
  after_resources = (mod_rc_rusage *)apr_pcalloc(r->pool, sizeof(mod_rc_rusage));
  mod_rc_rusage *use_resources;
  use_resources = (mod_rc_rusage *)apr_pcalloc(r->pool, sizeof(mod_rc_rusage));

  mod_rc_client_data *cdata;
  cdata = (mod_rc_client_data *)apr_pcalloc(r->pool, sizeof(mod_rc_client_data));

  if (resource_checker_initialized == 0) {
    return OK;
  }

  if (r->main && (stat(r->filename, &sb) == -1) && errno == ENOENT) {
    return OK;
  }

  cdata->access_uri = r->uri;
  cdata->access_file = r->filename;
#ifdef __APACHE24__
  cdata->access_src_ip = r->connection->client_ip;
#else
  cdata->access_src_ip = r->connection->remote_ip;
#endif
  cdata->access_dst_host = r->server->server_hostname;

  if (dconf->check_status == ON) {
    _mod_resource_checker_logging(r, 0, 0, NULL, dconf, cdata, MODULE_NAME, "RCheckSTATUS", NULL, r->pool);
  }

  // threashould check
  if (before_resources == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "%s NOTICE %s: Can not check resource of the request: file = %s",
                  MODULE_NAME, __func__, r->filename);
    return DECLINED;
  }

  match = 0;
  after_resources->cpu_utime = INITIAL_VALUE;
  after_resources->cpu_stime = INITIAL_VALUE;
  after_resources->shared_mem = INITIAL_VALUE;

  if (dconf->cpu_utime > INITIAL_VALUE || dconf->check_all == ON) {
    match = 1;
    if (dconf->check_all == ON)
      after_resources->cpu_utime = _get_rusage_resource(r->pool, "ALL", "cpu_utime");
    else
      after_resources->cpu_utime = _get_rusage_resource(r->pool, dconf->utime_process_type, "cpu_utime");
  }

  if (dconf->cpu_stime > INITIAL_VALUE || dconf->check_all == ON) {
    match = 1;
    if (dconf->check_all == ON)
      after_resources->cpu_stime = _get_rusage_resource(r->pool, "ALL", "cpu_stime");
    else
      after_resources->cpu_stime = _get_rusage_resource(r->pool, dconf->stime_process_type, "cpu_stime");
  }

  if (dconf->shared_mem > INITIAL_VALUE || dconf->check_all == ON) {
    match = 1;
    if (dconf->check_all == ON)
      after_resources->shared_mem = _get_rusage_resource(r->pool, "ALL", "shared_mem");
    else
      after_resources->shared_mem = _get_rusage_resource(r->pool, dconf->mem_process_type, "shared_mem");
  }

  if (match == 0) {
    return OK;
  }

  use_resources->cpu_utime = after_resources->cpu_utime - before_resources->cpu_utime;
  use_resources->cpu_stime = after_resources->cpu_stime - before_resources->cpu_stime;
  use_resources->shared_mem = after_resources->shared_mem - before_resources->shared_mem;

  // unexpected value; resource is negative number
  if (use_resources->cpu_utime < 0) {
    use_resources->cpu_utime = 0;
  }
  if (use_resources->cpu_stime < 0) {
    use_resources->cpu_stime = 0;
  }
  if (use_resources->shared_mem < 0) {
    use_resources->shared_mem = 0;
  }

  if (dconf->cpu_utime > INITIAL_VALUE && use_resources->cpu_utime >= dconf->cpu_utime) {
    _mod_resource_checker_logging(r, use_resources->cpu_utime, dconf->cpu_utime, dconf->utime_process_type, dconf,
                                  cdata, MODULE_NAME, "RCheckUCPU", "sec", r->pool);
  }

  if (dconf->cpu_stime > INITIAL_VALUE && use_resources->cpu_stime >= dconf->cpu_stime) {
    _mod_resource_checker_logging(r, use_resources->cpu_stime, dconf->cpu_stime, dconf->stime_process_type, dconf,
                                  cdata, MODULE_NAME, "RCheckSCPU", "sec", r->pool);
  }

  if (dconf->shared_mem > INITIAL_VALUE && use_resources->shared_mem >= dconf->shared_mem) {
    _mod_resource_checker_logging(r, use_resources->shared_mem, dconf->shared_mem, dconf->mem_process_type, dconf,
                                  cdata, MODULE_NAME, "RCheckMEM", "MiB", r->pool);
  }

  if (dconf->check_all == ON && dconf->json_fmt == ON) {
    _mod_resource_checker_logging_all(r, use_resources, dconf, sconf, cdata, r->pool);
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
    AP_INIT_TAKE1("RCheckRealServerName", set_real_server_name, NULL, RSRC_CONF | ACCESS_CONF, "Set real server name"),
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
