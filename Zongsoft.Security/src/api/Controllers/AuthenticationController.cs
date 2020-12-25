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
 * This file is part of Zongsoft.Security library.
 *
 * The Zongsoft.Security is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3.0 of the License,
 * or (at your option) any later version.
 *
 * The Zongsoft.Security is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the Zongsoft.Security library. If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Zongsoft.Web;
using Zongsoft.Security.Membership;

namespace Zongsoft.Security.Web.Controllers
{
	[ApiController]
	[Area(Modules.Security)]
	[Route("{area}/{controller}/{action}")]
	public class AuthenticationController : ControllerBase
	{
		#region 公共方法
		[HttpPost("{verifier?}")]
		public Task<IActionResult> SigninAsync(string verifier, [FromBody]AuthenticationRequest request, [FromQuery]string scenario)
		{
			if(string.IsNullOrWhiteSpace(scenario))
				return Task.FromResult((IActionResult)this.BadRequest());
			if(string.IsNullOrWhiteSpace(request.Identity))
				return Task.FromResult((IActionResult)this.BadRequest());

			var parameters = request.Parameters;

			//处理头部参数
			this.FillParameters(ref parameters);

			//如果参数数超过特定值则返回无效的请求
			if(parameters != null && parameters.Count > 10)
				return Task.FromResult((IActionResult)this.BadRequest());

			//进行身份验证
			var result = string.IsNullOrEmpty(verifier) ?
				Authentication.Instance.Authenticate(request.Identity, request.Password, request.Namespace, scenario, parameters) :
				Authentication.Instance.Authenticate(request.Identity, verifier, request.Token, request.Namespace, scenario, parameters);

			return result.Succeed ?
				Task.FromResult((IActionResult)this.Ok(result.Transform())) :
				Task.FromResult((IActionResult)this.StatusCode(403, new AuthenticationFailure(result)));
		}

		[HttpPost]
		[Authorize]
		public void Signout()
		{
			if(this.User is CredentialPrincipal credential)
				Authentication.Instance.Authority.Unregister(credential.CredentialId);
		}

		[Authorize]
		[HttpPost("{id:required}")]
		public Task<IActionResult> Renew(string id)
		{
			if(string.IsNullOrWhiteSpace(id))
				return Task.FromResult((IActionResult)this.BadRequest());

			if(this.User is CredentialPrincipal credential)
			{
				var principal = Authentication.Instance.Authority.Renew(credential.CredentialId, id);

				return principal == null ?
					Task.FromResult((IActionResult)this.BadRequest()) :
					Task.FromResult((IActionResult)this.Ok(ClaimsPrincipalTransformer.Default.Transform(principal)));
			}

			return Task.FromResult((IActionResult)this.Unauthorized());
		}
		#endregion

		#region 私有方法
		private void FillParameters(ref IDictionary<string, object> parameters)
		{
			const string X_PARAMETER_PREFIX = "x-parameter-";

			if(parameters == null)
				parameters = new Dictionary<string, object>();

			foreach(var header in this.Request.Headers)
			{
				if(header.Key.Length > X_PARAMETER_PREFIX.Length &&
				   header.Key.StartsWith(X_PARAMETER_PREFIX, StringComparison.OrdinalIgnoreCase))
				{
					parameters.Add(header.Key.Substring(X_PARAMETER_PREFIX.Length), string.Join("|", header.Value));
				}
			}
		}
		#endregion

		#region 嵌套子类
		public struct AuthenticationRequest
		{
			#region 公共属性
			public string Identity { get; set; }
			public string Password { get; set; }
			public string Token { get; set; }
			public string Namespace { get; set; }
			public IDictionary<string, object> Parameters { get; set; }
			#endregion
		}

		public struct AuthenticationFailure
		{
			#region 构造函数
			public AuthenticationFailure(AuthenticationResult result)
			{
				this.Reason = result.Reason;
				this.Message = result.Exception?.Message;
			}
			#endregion

			#region 公共属性
			public string Reason { get; }
			public string Message { get; }
			#endregion
		}
		#endregion
	}

	[ApiController]
	[Area(Modules.Security)]
	[Route("{area}/Authentication/Verification")]
	public class AuthenticationVerifierController : ControllerBase
	{
		[HttpPost("Issue/{verifier}:{key}")]
		[HttpPost("Issue/{verifier}:{key}!{namespace:required}")]
		public Task<IActionResult> Issue(string verifier, string key, string @namespace)
		{
			if(string.IsNullOrWhiteSpace(key))
				return Task.FromResult((IActionResult)this.BadRequest());

			if(!string.IsNullOrWhiteSpace(@namespace))
				key = key + "!" + @namespace;

			Authentication.Instance.Authenticator.Verification.GetVerifier(verifier).Issue(key);
			return Task.FromResult((IActionResult)this.NoContent());
		}

		[HttpPost("Verify/{verifier}:{key}")]
		[HttpPost("Verify/{verifier}:{key}!{namespace:required}")]
		public async Task<IActionResult> Verify(string verifier, string key, string @namespace)
		{
			var token = await this.Request.ReadAsStringAsync();

			if(!string.IsNullOrWhiteSpace(@namespace))
				key = key + "!" + @namespace;

			if(Authentication.Instance.Authenticator.Verification.GetVerifier(verifier).Verify(key, token))
				return this.NoContent();

			return this.NotFound();
		}
	}
}
