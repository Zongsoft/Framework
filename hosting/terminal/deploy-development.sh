#!/bin/sh

dotnet deploy -cloud:aliyun -site:daemon -edition:Debug -environment:development -framework:net7.0
