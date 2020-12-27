/*
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
 * Copyright (C) 2010-2020 Zongsoft Studio <http://www.zongsoft.com>
 *
 * This file is part of Zongsoft.Core library.
 *
 * The Zongsoft.Core is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3.0 of the License,
 * or (at your option) any later version.
 *
 * The Zongsoft.Core is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the Zongsoft.Core library. If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Text;
using System.Collections.Generic;

using Zongsoft.Common;
using Zongsoft.Caching;

namespace Zongsoft.Security
{
	public abstract class Invitation<TKey> : IInvitation<TKey> where TKey : struct, IEquatable<TKey>
	{
		#region 构造函数
		protected Invitation(string name, ICache cache = null)
		{
			this.Name = name;
			this.Cache = cache;
		}
		#endregion

		#region 公共属性
		public string Name { get; }
		public ICache Cache { get; set; }
		#endregion

		public (string token, string extra) Get(TKey key, out bool durability)
		{
			var cache = this.Cache ?? throw new InvalidOperationException($"Missing the required cache service.");

			if(cache.TryGetValue(GetCacheKey(key), out string token) && token != null && token.Length > 0)
				return (token, this.Get(token, out durability).extra);

			durability = false;
			return default;
		}

		public (TKey key, string extra) Get(string token, out bool durability)
		{
			var cache = this.Cache ?? throw new InvalidOperationException($"Missing the required cache service.");

			if(cache.TryGetValue(GetCacheKey(token), out byte[] buffer) && buffer != null && buffer.Length > 1)
			{
				var data = buffer.AsSpan();

				durability = data[0] != 0;

				if(data[1] > 0)
				{
					var key = this.DeserializeKey(data.Slice(2, data[1]));
					var extra = data[1] < buffer.Length - 2 ? Encoding.UTF8.GetString(data.Slice(data[1] + 2)) : null;

					return (key, extra);
				}
			}

			durability = false;
			return default;
		}

		public string Invite(TKey key, string extra, bool durability, TimeSpan expiry)
		{
			var cache = this.Cache ?? throw new InvalidOperationException($"Missing the required cache service.");
			var keyed = this.SerializeKey(key);

			if(keyed.Length > byte.MaxValue)
				throw new InvalidOperationException($"");

			var bytes = Encoding.UTF8.GetBytes(extra);
			var data = new byte[keyed.Length + bytes.Length + 2];
			data[0] = (byte)(durability ? 1 : 0);
			data[1] = (byte)keyed.Length;
			Array.Copy(keyed, 0, data, 2, keyed.Length);
			Array.Copy(bytes, 0, data, keyed.Length + 2, bytes.Length);

			if(expiry == TimeSpan.Zero || expiry.TotalDays > 31)
				expiry = TimeSpan.FromDays(1);

			var token = Randomizer.GenerateString(12);

			if(cache.SetValue(GetCacheKey(token), data, expiry, CacheRequisite.Always) &&
			   cache.SetValue(GetCacheKey(key), token, expiry, CacheRequisite.Always))
				return token;

			return null;
		}

		public bool Revoke(TKey key)
		{
			var cache = this.Cache ?? throw new InvalidOperationException($"Missing the required cache service.");

			if(cache.TryGetValue(GetCacheKey(key), out string token))
				return cache.Remove(new[] { GetCacheKey(key), GetCacheKey(token) }) > 0;

			return false;
		}

		public bool Verify(string token)
		{
			var cache = this.Cache ?? throw new InvalidOperationException($"Missing the required cache service.");
			return cache.Exists(GetCacheKey(token));
		}

		public void Accept(string identity, string token, IDictionary<string, object> parameters = null)
		{
			throw new NotImplementedException();
		}

		protected virtual byte[] SerializeKey(TKey key) => Encoding.UTF8.GetBytes(key.ToString());
		protected abstract TKey DeserializeKey(Span<byte> data);

		private string GetCacheKey(TKey key) => $"Zongsoft.Invitation:{this.Name}:{key}";
		private string GetCacheKey(string token) => $"Zongsoft.Invitation:{this.Name}:#{token}";
	}
}
