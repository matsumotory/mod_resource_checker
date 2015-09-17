add_config(
  "TotalRequests"         => 10,                       # int
  "Concurrency"           => 10,                        # int max 20000
  "KeepAlive"             => true,                      # true or false or nil
  "ShowProgress"          => false,                      # true, false or nil
  "ShowPercentile"        => false,                      # true, false or nil
  "ShowConfidence"        => false,                      # true, false or nil
  "VerboseLevel"          => 1,                         # int 1 ~ 5
  "AddHeader"             => 'Host: test001.example.local',
)

