#!/bin/bash
############################## DEV_SCRIPT_MARKER ##############################
# This script is used to document and run recurring tasks in development.     #
#                                                                             #
# You can run your tasks using the script `./dev some-task`.                  #
# You can install the Sandstorm Dev Script Runner and run your tasks from any #
# nested folder using `dev some-task`.                                        #
# https://github.com/sandstorm/Sandstorm.DevScriptRunner                      #
###############################################################################

set -e

######### TASKS #########

# Build the package
function build() {
  go build main.go
}

# Run the built module
function run() {
  build
  ./main $@
}


####### Utilities #######

_log_success() {
  printf "\033[0;32m%s\033[0m\n" "${1}"
}
_log_warning() {
  printf "\033[1;33m%s\033[0m\n" "${1}"
}
_log_error() {
  printf "\033[0;31m%s\033[0m\n" "${1}"
}

# THIS NEEDS TO BE LAST!!!
# this will run your tasks
"$@"
