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
 * Copyright (C) 2010-2023 Zongsoft Studio <http://www.zongsoft.com>
 *
 * This file is part of Zongsoft.Externals.Redis library.
 *
 * The Zongsoft.Externals.Redis is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3.0 of the License,
 * or (at your option) any later version.
 *
 * The Zongsoft.Externals.Redis is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the Zongsoft.Externals.Redis library. If not, see <http://www.gnu.org/licenses/>.
 */

using System;

using StackExchange.Redis;

namespace Zongsoft.Externals.Redis
{
	public static class RedisUtility
	{
		public static string IncreaseId(ReadOnlySpan<char> id)
		{
			if(id.IsEmpty || (id.Length == 1 && (id[0] == '0' || id[0] == '-')))
				return "0-1";

			long value;
			var index = id.LastIndexOf('-');

			if(index < 0) //没有分隔符
				return long.TryParse(id, out value) ? $"{value}-1" : throw IllegalId(id);

			if(index == 0) //分隔符位于首字符
				return long.TryParse(id[1..], out value) ? $"0-{value + 1}" : throw IllegalId(id);

			if(index == id.Length - 1) //分隔符位于最末尾
				return $"{id}1";

			return long.TryParse(id[(index + 1)..], out value) ? $"{id[..index]}-{value + 1}" : throw IllegalId(id);
		}

		public static string DecreaseId(ReadOnlySpan<char> id)
		{
			if(id.IsEmpty || (id.Length == 1 && (id[0] == '0' || id[0] == '-')) || id == "0-0")
				return "0";

			long value;
			var index = id.LastIndexOf('-');

			if(index < 0) //没有分隔符
				return long.TryParse(id, out value) ? $"{value - 1}-{long.MaxValue}" : throw IllegalId(id);

			if(index == 0) //分隔符位于首字符
				return long.TryParse(id[1..], out value) ? value > 1 ? $"0-{value - 1}" : "0" : throw IllegalId(id);

			if(index == id.Length - 1) //分隔符位于最末尾
				return long.TryParse(id[0..index], out value) ? (value > 0 ? $"{value - 1}-{long.MaxValue}" : "0") : throw IllegalId(id);

			if(long.TryParse(id[(index + 1)..], out value))
			{
				if(value > 0)
					return $"{id[..index]}-{value - 1}";

				if(long.TryParse(id[0..index], out value))
					return value > 0 ? $"{value - 1}-{long.MaxValue}" : "0";
			}

			throw IllegalId(id);
		}

		[System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
		private static Exception IllegalId(ReadOnlySpan<char> id) => new ArgumentException($"The specified '{id}' is an invalid message id value.");

		public static RedisQueuePendingMessageInfo[] GetPendingMessages(this IDatabase database, string key, string group, TimeSpan idle, int count = 100, string minimum = "-", string maximum = "+") =>
			GetPendingMessages(database, key, group, null, idle > TimeSpan.Zero ? (long)idle.TotalMilliseconds : 0L, count, minimum, maximum);

		public static RedisQueuePendingMessageInfo[] GetPendingMessages(this IDatabase database, string key, string group, string consumer = null, int count = 100, string minimum = "-", string maximum = "+") =>
			GetPendingMessages(database, key, group, consumer, 0L, count, minimum, maximum);

		public static RedisQueuePendingMessageInfo[] GetPendingMessages(this IDatabase database, string key, string group, string consumer, TimeSpan idle, int count = 100, string minimum = "-", string maximum = "+") =>
			GetPendingMessages(database, key, group, consumer, idle > TimeSpan.Zero ? (long)idle.TotalMilliseconds : 0L, count, minimum, maximum);

		private static RedisQueuePendingMessageInfo[] GetPendingMessages(this IDatabase database, string key, string group, string consumer, long idle = 0, int count = 100, string minimum = "-", string maximum = "+")
		{
			if(database == null)
				throw new ArgumentNullException(nameof(database));
			if(string.IsNullOrEmpty(key))
				throw new ArgumentNullException(nameof(key));
			if(string.IsNullOrEmpty(group))
				throw new ArgumentNullException(nameof(group));

			if(count < 1)
				count = 100;
			if(string.IsNullOrEmpty(minimum))
				minimum = "-";
			if(string.IsNullOrEmpty(maximum))
				maximum = "+";

			object[] args;

			if(idle > 0)
				args = string.IsNullOrEmpty(consumer) ?
					new object[] { key, group, "IDLE", idle, minimum, maximum, count } :
					new object[] { key, group, "IDLE", idle, minimum, maximum, count, consumer };
			else
				args = string.IsNullOrEmpty(consumer) ?
					new object[] { key, group, minimum, maximum, count } :
					new object[] { key, group, minimum, maximum, count, consumer };

			var result = database.Execute(@"XPENDING", args);

			if(result == null || result.IsNull || result.Type != ResultType.MultiBulk)
				return Array.Empty<RedisQueuePendingMessageInfo>();

			var infos = (RedisResult[])result;
			if(infos == null || infos.Length == 0)
				return Array.Empty<RedisQueuePendingMessageInfo>();

			var pendings = new RedisQueuePendingMessageInfo[infos.Length];

			for(int i = 0; i < infos.Length; i++)
			{
				var values = (RedisValue[])infos[i];

				if(values == null || values.Length == 0)
					continue;

				switch(values.Length)
				{
					case 1:
						pendings[i] = new RedisQueuePendingMessageInfo(values[0], RedisValue.Null);
						break;
					case 2:
						pendings[i] = new RedisQueuePendingMessageInfo(values[0], values[1]);
						break;
					case 3:
						pendings[i] = new RedisQueuePendingMessageInfo(values[0], values[1], (long)values[2]);
						break;
					case 4:
						pendings[i] = new RedisQueuePendingMessageInfo(values[0], values[1], (long)values[2], (int)values[3]);
						break;
				}
			}

			return pendings;
		}

		internal static string GetQueueName(string name, string topic) => string.IsNullOrWhiteSpace(topic) ? $"Zongsoft.Queue:{name}" : $"Zongsoft.Queue:{name}:{topic}";
	}

	public readonly struct RedisQueuePendingMessageInfo
	{
		public RedisQueuePendingMessageInfo(RedisValue messageId, RedisValue consumer, long idleTimeInMs = 0L, int deliveryCount = 0)
		{
			MessageId = messageId;
			Consumer = consumer;
			IdledDuration = idleTimeInMs > 0 ? TimeSpan.FromMilliseconds(idleTimeInMs) : TimeSpan.Zero;
			DeliveryCount = deliveryCount;
		}

		public RedisValue MessageId { get; }
		public RedisValue Consumer { get; }
		public TimeSpan IdledDuration { get; }
		public int DeliveryCount { get; }
	}
}