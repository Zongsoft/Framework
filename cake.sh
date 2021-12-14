#!/bin/sh

set -ex

CAKE_ARGS="--verbosity=verbose"

PROJECT_CORE="Zongsoft.Core/build.cake"
PROJECT_DATA="Zongsoft.Data/build.cake"
PROJECT_NET="Zongsoft.Net/build.cake"
PROJECT_WEB="Zongsoft.Web/build.cake"
PROJECT_PLUGINS="Zongsoft.Plugins/build.cake"
PROJECT_PLUGINS_WEB="Zongsoft.Plugins.Web/build.cake"
PROJECT_SCHEDULING="Zongsoft.Scheduling/build.cake"
PROJECT_SECURITY="Zongsoft.Security/build.cake"
PROJECT_COMMANDS="Zongsoft.Commands/build.cake"
PROJECT_REPORTING="Zongsoft.Reporting/build.cake"
PROJECT_MESSAGING_MQTT="Zongsoft.Messaging.Mqtt/build.cake"
PROJECT_ALIYUN="externals/aliyun/build.cake"
PROJECT_REDIS="externals/redis/build.cake"
PROJECT_WECHAT="externals/wechat/build.cake"
PROJECT_GRAPECITY="externals/grapecity/build.cake"

dotnet tool restore

dotnet cake $PROJECT_CORE $CAKE_ARGS "$@"
dotnet cake $PROJECT_DATA $CAKE_ARGS "$@"
dotnet cake $PROJECT_NET $CAKE_ARGS "$@"
dotnet cake $PROJECT_WEB $CAKE_ARGS "$@"
dotnet cake $PROJECT_PLUGINS $CAKE_ARGS "$@"
dotnet cake $PROJECT_PLUGINS_WEB $CAKE_ARGS "$@"
dotnet cake $PROJECT_SCHEDULING $CAKE_ARGS "$@"
dotnet cake $PROJECT_SECURITY $CAKE_ARGS "$@"
dotnet cake $PROJECT_COMMANDS $CAKE_ARGS "$@"
dotnet cake $PROJECT_REPORTING $CAKE_ARGS "$@"
dotnet cake $PROJECT_MESSAGING_MQTT $CAKE_ARGS "$@"
dotnet cake $PROJECT_ALIYUN $CAKE_ARGS "$@"
dotnet cake $PROJECT_REDIS $CAKE_ARGS "$@"
dotnet cake $PROJECT_WECHAT $CAKE_ARGS "$@"
dotnet cake $PROJECT_GRAPECITY $CAKE_ARGS "$@"
