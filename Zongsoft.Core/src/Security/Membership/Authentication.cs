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

namespace Zongsoft.Security.Membership
{
	/// <summary>
	/// 提供身份验证的平台类。
	/// </summary>
	[System.Reflection.DefaultMember(nameof(Authenticator))]
	public class Authentication
	{
		#region 静态变量
		private static readonly DateTime EPOCH = new DateTime(2000, 1, 1);
		#endregion

		#region 单例字段
		public static readonly Authentication Instance = new Authentication();
		#endregion

		#region 构造函数
		private Authentication()
		{
			this.Challengers = new List<IAuthenticationChallenger>();
			this.Transformers = new Collections.NamedCollection<IClaimsIdentityTransformer>(transformer => transformer.Name);
		}
		#endregion

		#region 公共属性
		/// <summary>
		/// 获取或设置凭证主体的提供程序。
		/// </summary>
		public ICredentialProvider Authority { get; set; }

		/// <summary>
		/// 获取或设置身份验证器。
		/// </summary>
		public IAuthenticator Authenticator { get; set; }

		/// <summary>
		/// 获取一个身份验证验证器集合。
		/// </summary>
		public ICollection<IAuthenticationChallenger> Challengers { get; }

		/// <summary>
		/// 获取一个身份转换器集合。
		/// </summary>
		public Collections.INamedCollection<IClaimsIdentityTransformer> Transformers { get; }
		#endregion

		#region 公共方法
		public AuthenticationResult Authenticate(string identity, string verifier, string token, string @namespace, string scenario, IDictionary<string, object> parameters)
		{
			var authenticator = this.Authenticator ?? throw new InvalidOperationException("Missing the required authenticator.");
			return this.OnAuthenticated(authenticator, scenario, authenticator.Authenticate(identity, verifier, token, @namespace, scenario, parameters));
		}

		public AuthenticationResult Authenticate(string identity, string password, string @namespace, string scenario, IDictionary<string, object> parameters)
		{
			var authenticator = this.Authenticator ?? throw new InvalidOperationException("Missing the required authenticator.");
			return this.OnAuthenticated(authenticator, scenario, authenticator.Authenticate(identity, password, @namespace, scenario, parameters));
		}
		#endregion

		#region 私有方法
		private AuthenticationResult OnAuthenticated(IAuthenticator authenticator, string scenario, AuthenticationResult result)
		{
			if(result == null)
				return null;

			if(result.Succeed)
				result.Principal = new CredentialPrincipal(GenerateId(out var token), token, scenario, result.Identity);

			var context = new AuthenticationContext(authenticator.Scheme, scenario, result);

			foreach(var challenger in this.Challengers)
			{
				challenger.Challenge(context);
			}

			if(context.Succeed)
			{
				authenticator.OnChallenged(context);

				if(context.Principal is CredentialPrincipal principal)
					this.Authority.Register(principal);
			}

			return context.Result;
		}
		#endregion

		#region 静态方法
		public static string GenerateId()
		{
			return ((ulong)(DateTime.UtcNow - EPOCH).TotalSeconds).ToString() + Common.Randomizer.GenerateString(8);
		}

		public static string GenerateId(out string token)
		{
			token = ((ulong)(DateTime.UtcNow - EPOCH).TotalDays).ToString() + Environment.TickCount64.ToString("X") + Common.Randomizer.GenerateString(8);
			return GenerateId();
		}
		#endregion
	}
}
