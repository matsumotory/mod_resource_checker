# print ab-mruby headers
# define test suite
test_suite do
  "TargetServerHost".should_be               "127.0.0.1"
  "TargetServerPort".should_be               8080
  "TargetDocumentPath".should_be             "/cgi-bin/loop.cgi"
  "WriteErrors".should_be                    0
  "CompleteRequests".should_be               10
  "ConnetcErrors".should_be                  0
  "ReceiveErrors".should_be                  0
  "ExceptionsErrors".should_be               0
  "Non2xxResponses".should_be_over           0
end

test_run
