﻿/*
 *   _____                                ______
 *  /_   /  ____  ____  ____  _________  / __/ /_
 *    / /  / __ \/ __ \/ __ \/ ___/ __ \/ /_/ __/
 *   / /__/ /_/ / / / / /_/ /\_ \/ /_/ / __/ /_
 *  /____/\____/_/ /_/\__  /____/\____/_/  \__/
 *                   /____/
 *
 * Authors:
 *   钟峰(Popeye Zhong) <zongsoft@gmail.com>
 *
 * Copyright (C) 2010-2022 Zongsoft Studio <http://www.zongsoft.com>
 *
 * This file is part of Zongsoft.Externals.Hangfire library.
 *
 * The Zongsoft.Externals.Hangfire is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3.0 of the License,
 * or (at your option) any later version.
 *
 * The Zongsoft.Externals.Hangfire is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the Zongsoft.Externals.Hangfire library. If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Linq;
using System.Collections.Generic;

using Hangfire.Server;
using Hangfire.States;
using Hangfire.Storage;
using Hangfire.Logging;
using Hangfire.Annotations;

using Zongsoft.Services;
using Zongsoft.Configuration;

namespace Zongsoft.Externals.Hangfire.Storages
{
	[Service(typeof(global::Hangfire.JobStorage))]
	public class RedisStorage : global::Hangfire.JobStorage
	{
		private readonly object _lock = new();
		private global::Hangfire.Redis.StackExchange.RedisStorage _storage;

		public RedisStorage() { }

		public global::Hangfire.Redis.StackExchange.RedisStorage Storage
		{
			get
			{
				if(_storage == null)
				{
					lock(_lock)
					{
						_storage ??= new global::Hangfire.Redis.StackExchange.RedisStorage(GetRedisConnection());
					}
				}

				return _storage;
			}
		}

		private static ConnectionSetting GetConnectionSetting(ConnectionSettingCollection settings)
		{
			if(settings == null || settings.Count == 0)
				return null;

			if(settings.TryGet("Hangfire", out var setting))
				return setting;

			setting = settings.GetDefault();
			if(setting != null)
				return setting;

			return settings.FirstOrDefault(setting => setting != null && string.Equals(setting.Driver, "redis", StringComparison.OrdinalIgnoreCase));
		}

		private static StackExchange.Redis.ConnectionMultiplexer GetRedisConnection() =>
			GetRedisConnection(GetConnectionSetting(ApplicationContext.Current?.Configuration?.GetOption<ConnectionSettingCollection>("/Externals/Redis/ConnectionSettings")));
		private static StackExchange.Redis.ConnectionMultiplexer GetRedisConnection(IConnectionSetting connectionSetting) =>
			StackExchange.Redis.ConnectionMultiplexer.Connect(GetRedisConfiguration(connectionSetting));

		private static StackExchange.Redis.ConfigurationOptions GetRedisConfiguration(IConnectionSetting connectionSetting)
		{
			if(connectionSetting == null)
				return null;

			var host = connectionSetting.Values.Server;
			if(connectionSetting.Values.Port != 0)
				host += $":{connectionSetting.Values.Port}";

			var entries = connectionSetting.Values.Mapping
					.Where(entry =>
						!string.IsNullOrEmpty(entry.Key) &&
						!entry.Key.Equals(nameof(ConnectionSetting.Values.Server), StringComparison.OrdinalIgnoreCase) &&
						!entry.Key.Equals(nameof(ConnectionSetting.Values.Port), StringComparison.OrdinalIgnoreCase))
					.Select(entry => $"{entry.Key}={entry.Value}");

			var connectionString = entries.Any() ? $"{host},{string.Join(',', entries)}" : host;
			return StackExchange.Redis.ConfigurationOptions.Parse(connectionString, true);
		}

		public override bool LinearizableReads => this.Storage.LinearizableReads;
#pragma warning disable CS0618 // 类型或成员已过时
		public override IEnumerable<IServerComponent> GetComponents() => this.Storage.GetComponents();
#pragma warning restore CS0618 // 类型或成员已过时
		public override IMonitoringApi GetMonitoringApi() => this.Storage.GetMonitoringApi();
		public override IStorageConnection GetConnection() => this.Storage.GetConnection();
		public override IStorageConnection GetReadOnlyConnection() => this.Storage.GetReadOnlyConnection();
		public override IEnumerable<IStateHandler> GetStateHandlers() => this.Storage.GetStateHandlers();
		public override bool HasFeature([NotNull] string featureId) => this.Storage.HasFeature(featureId);
		public override void WriteOptionsToLog(ILog logger) => this.Storage.WriteOptionsToLog(logger);
		public override bool Equals(object obj) => this.Storage.Equals(obj);
		public override int GetHashCode() => this.Storage.GetHashCode();
		public override string ToString() => this.Storage.ToString();
	}
}