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
using System.Collections.Generic;

namespace Zongsoft.Security
{
	public struct IdentityVerifierResult
	{
		#region 私有构造
		private IdentityVerifierResult(string key, string token, IDictionary<string, object> parameters = null)
		{
			if(string.IsNullOrEmpty(key))
				throw new ArgumentNullException(nameof(key));

			if(string.IsNullOrEmpty(token))
				throw new ArgumentNullException(nameof(token));

			this.Failure = null;
			this.Key = key;
			this.Token = token;
			this.Parameters = parameters;
		}

		private IdentityVerifierResult(string key, Exception exception, IDictionary<string, object> parameters = null)
		{
			if(string.IsNullOrEmpty(key))
				throw new ArgumentNullException(nameof(key));

			this.Failure = exception;
			this.Key = key;
			this.Token = null;
			this.Parameters = parameters;
		}
		#endregion

		#region 公共属性
		public bool Succeed { get => Failure == null; }
		public bool Failed { get => Failure != null; }

		public Exception Failure { get; }
		public string Sequence { get; }
		public string Key { get; }
		public string Token { get; }
		public IDictionary<string, object> Parameters { get; }
		#endregion

		#region 静态方法
		public static IdentityVerifierResult Success(string key, string token, IDictionary<string, object> parameters = null)
		{
			return new IdentityVerifierResult(key, token, parameters);
		}

		public static IdentityVerifierResult Fail(string key, Exception exception, IDictionary<string, object> parameters = null)
		{
			return new IdentityVerifierResult(key, exception, parameters);
		}
		#endregion
	}
}
