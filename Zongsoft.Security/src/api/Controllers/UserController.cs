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
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;

using Zongsoft.Web;
using Zongsoft.Data;
using Zongsoft.Services;
using Zongsoft.Security.Membership;

namespace Zongsoft.Security.Web.Controllers
{
	[ApiController]
	[Area(Modules.Security)]
	[Authorize]
	[Route("[area]/Users")]
	public class UserController : ControllerBase
	{
		#region 成员字段
		private IUserProvider<IUser> _userProvider;
		private IAuthorizer _authorizer;
		private IMemberProvider<IRole, IUser> _memberProvider;
		private IPermissionProvider _permissionProvider;
		#endregion

		#region 公共属性
		[ServiceDependency(IsRequired = true)]
		public IAuthorizer Authorizer
		{
			get => _authorizer;
			set => _authorizer = value ?? throw new ArgumentNullException();
		}

		[ServiceDependency(IsRequired = true)]
		public IUserProvider<IUser> UserProvider
		{
			get => _userProvider;
			set => _userProvider = value ?? throw new ArgumentNullException();
		}

		[ServiceDependency(IsRequired = true)]
		public IMemberProvider<IRole, IUser> MemberProvider
		{
			get => _memberProvider;
			set => _memberProvider = value ?? throw new ArgumentNullException();
		}

		[ServiceDependency(IsRequired = true)]
		public IPermissionProvider PermissionProvider
		{
			get => _permissionProvider;
			set => _permissionProvider = value ?? throw new ArgumentNullException();
		}
		#endregion

		#region 公共方法
		[HttpGet("{id:long}")]
		public Task<IActionResult> Get(uint id)
		{
			var user = this.UserProvider.GetUser(id);

			return user != null ?
				Task.FromResult((IActionResult)this.Ok(user)) :
				Task.FromResult((IActionResult)this.NotFound());
		}

		[HttpGet("{identity?}")]
		[HttpGet("{namespace:required}:{identity:required}")]
		public Task<IActionResult> Get(string @namespace, string identity, [FromQuery]Paging page = null)
		{
			if(string.IsNullOrEmpty(identity) || identity == "*")
				return Task.FromResult(WebUtility.Paginate(this.UserProvider.GetUsers(@namespace, page ?? Paging.Page(1))));

			var result = this.UserProvider.GetUser(identity, @namespace);

			return result != null ?
				Task.FromResult((IActionResult)this.Ok(result)) :
				Task.FromResult((IActionResult)this.NoContent());
		}

		[HttpDelete("{id}")]
		public Task<IActionResult> Delete(uint id)
		{
			if(id == 0)
				return Task.FromResult((IActionResult)this.BadRequest());

			return this.UserProvider.Delete(id) > 0 ?
				Task.FromResult((IActionResult)this.NoContent()) :
				Task.FromResult((IActionResult)this.NotFound());
		}

		[HttpDelete]
		public async Task<IActionResult> DeleteAsync()
		{
			var content = await this.Request.ReadAsStringAsync();

			if(string.IsNullOrWhiteSpace(content))
				return this.BadRequest();

			var ids = Common.StringExtension.Slice<uint>(content, new[] { ',', '|' }, uint.TryParse).ToArray();

			if(ids == null || ids.Length == 0)
				return this.BadRequest();

			return this.UserProvider.Delete(ids) > 0 ?
				(IActionResult)this.NoContent() :
				(IActionResult)this.NotFound();
		}

		[AllowAnonymous]
		[HttpPost("Register")]
		public IActionResult Register([FromBody]RegisterEntity entity, [FromQuery]string token)
		{
			var user = this.UserProvider.Register(entity.Namespace, entity.Identity, token, entity.Password, entity.Parameters);
			return user == null ? (IActionResult)this.NoContent() : this.Ok(user);
		}

		[HttpPost]
		[ProducesResponseType(StatusCodes.Status201Created)]
		[ProducesResponseType(StatusCodes.Status409Conflict)]
		[ProducesResponseType(StatusCodes.Status400BadRequest)]
		public ActionResult<IUser> Create([FromBody]IUser model)
		{
			if(model == null)
				return this.BadRequest();

			//从请求消息的头部获取指定的用户密码
			this.Request.Headers.TryGetValue("x-password", out var password);

			if(this.UserProvider.Create(model, password))
				return this.CreatedAtAction(nameof(Get), new { id = model.UserId }, model);

			return this.Conflict();
		}

		[HttpPut("{id?}")]
		[HttpPatch("{id?}")]
		public Task<IActionResult> Update(uint id, [FromBody]IUser model)
		{
			return this.UserProvider.Update(id, model) ?
				Task.FromResult((IActionResult)this.NoContent()) :
				Task.FromResult((IActionResult)this.NotFound());
		}

		[HttpPatch("{id}/Namespace")]
		[HttpPatch("Namespace/{id?}")]
		public async Task<IActionResult> SetNamespace(uint id)
		{
			var content = await this.Request.ReadAsStringAsync();

			if(string.IsNullOrWhiteSpace(content))
				return this.BadRequest();

			return this.UserProvider.SetNamespace(id, content) ? (IActionResult)this.NoContent() : this.NotFound();
		}

		[HttpPatch("{id}/Name")]
		[HttpPatch("Name/{id?}")]
		public async Task<IActionResult> SetName(uint id)
		{
			var content = await this.Request.ReadAsStringAsync();

			if(string.IsNullOrWhiteSpace(content))
				return this.BadRequest();

			return this.UserProvider.SetName(id, content) ? (IActionResult)this.NoContent() : this.NotFound();
		}

		[Authorize]
		[HttpPatch("{id}/FullName")]
		[HttpPatch("FullName/{id?}")]
		public async Task<IActionResult> SetFullName(uint id)
		{
			var content = await this.Request.ReadAsStringAsync();

			if(string.IsNullOrWhiteSpace(content))
				return this.BadRequest();

			return this.UserProvider.SetFullName(id, content) ? (IActionResult)this.NoContent() : this.NotFound();
		}

		[HttpPatch("{id}/Email/{verifier}:{secret}")]
		[HttpPatch("Email/{verifier}:{secret}")]
		public async Task<IActionResult> SetEmail(uint id, string verifier, string secret)
		{
			var content = await this.Request.ReadAsStringAsync();

			if(string.IsNullOrWhiteSpace(content))
				return this.BadRequest();

			return this.UserProvider.SetEmail(id, content, verifier, secret) ?
				(IActionResult)this.NoContent() :
				(IActionResult)this.NotFound();
		}

		[HttpPatch("{id}/Phone/{verifier}:{secret}")]
		[HttpPatch("Phone/{verifier}:{secret}")]
		public async Task<IActionResult> SetPhone(uint id, string verifier, string secret)
		{
			var content = await this.Request.ReadAsStringAsync();

			if(string.IsNullOrWhiteSpace(content))
				return this.BadRequest();

			return this.UserProvider.SetPhone(id, content, verifier, secret) ?
				(IActionResult)this.NoContent() :
				(IActionResult)this.NotFound();
		}

		[HttpPatch("{id}/Description")]
		[HttpPatch("Description/{id?}")]
		public async Task<IActionResult> SetDescription(uint id)
		{
			var content = await this.Request.ReadAsStringAsync();

			if(string.IsNullOrWhiteSpace(content))
				return this.BadRequest();

			return this.UserProvider.SetDescription(id, content) ? (IActionResult)this.NoContent() : this.NotFound();
		}

		[HttpPatch("{id}/Status/{value}")]
		[HttpPatch("Status/{value}")]
		public Task<IActionResult> SetStatus(uint id, UserStatus value)
		{
			return this.UserProvider.SetStatus(id, value) ?
				Task.FromResult((IActionResult)this.NoContent()) :
				Task.FromResult((IActionResult)this.NotFound());
		}

		[HttpHead("{id}")]
		[HttpGet("{id}/exists")]
		[HttpGet("exists")]
		public Task<IActionResult> Exists(uint id)
		{
			return this.UserProvider.Exists(id) ?
				Task.FromResult((IActionResult)this.NoContent()) :
				Task.FromResult((IActionResult)this.NotFound());
		}

		[AllowAnonymous]
		[HttpHead("{namespace}:{identity}")]
		[HttpGet("exists/{namespace}:{identity}")]
		public Task<IActionResult> Exists(string @namespace, string identity)
		{
			if(string.IsNullOrWhiteSpace(identity))
				return Task.FromResult((IActionResult)this.BadRequest());

			return this.UserProvider.Exists(identity, @namespace) ?
				Task.FromResult((IActionResult)this.NoContent()) :
				Task.FromResult((IActionResult)this.NotFound());
		}
		#endregion

		#region 密码处理
		[HttpGet("{id}/Password.Has")]
		[HttpGet("Password.Has")]
		public Task<IActionResult> HasPassword(uint id = 0)
		{
			return this.UserProvider.HasPassword(id) ?
				Task.FromResult((IActionResult)this.NoContent()) :
				Task.FromResult((IActionResult)this.NotFound());
		}

		[AllowAnonymous]
		[HttpGet("Password.Has/{identity}")]
		[HttpGet("Password.Has/{namespace:required}:{identity}")]
		public Task<IActionResult> HasPassword(string @namespace, string identity)
		{
			if(string.IsNullOrWhiteSpace(identity))
				return Task.FromResult((IActionResult)this.BadRequest());

			return this.UserProvider.HasPassword(identity, @namespace) ?
				Task.FromResult((IActionResult)this.NoContent()) :
				Task.FromResult((IActionResult)this.NotFound());
		}

		[Authorize]
		[HttpPut("{id}/Password.Change")]
		[HttpPut("Password.Change")]
		public Task<IActionResult> ChangePassword(uint id, [FromBody]PasswordChangeEntity password)
		{
			return this.UserProvider.ChangePassword(id, password.OldPassword, password.NewPassword) ?
				Task.FromResult((IActionResult)this.NoContent()) :
				Task.FromResult((IActionResult)this.NotFound());
		}

		[AllowAnonymous]
		[HttpPost("Password.Forget/{identity}")]
		[HttpPost("Password.Forget/{namespace:required}:{identity}")]
		public Task<IActionResult> ForgetPassword(string @namespace, string identity)
		{
			if(string.IsNullOrWhiteSpace(identity))
				return Task.FromResult((IActionResult)this.BadRequest());

			var id = this.UserProvider.ForgetPassword(identity, @namespace);

			return id > 0 ?
				Task.FromResult((IActionResult)this.Ok(id)) :
				Task.FromResult((IActionResult)this.NotFound());
		}

		[AllowAnonymous]
		[HttpPost("{id}/Password.Reset")]
		[HttpPost("Password.Reset")]
		public Task<IActionResult> ResetPassword(uint id, [FromBody]PasswordResetEntity content)
		{
			if(string.IsNullOrWhiteSpace(content.Secret))
				return Task.FromResult((IActionResult)this.BadRequest());

			return this.UserProvider.ResetPassword(id, content.Secret, content.Password) ?
				Task.FromResult((IActionResult)this.NoContent()) :
				Task.FromResult((IActionResult)this.BadRequest());
		}

		[AllowAnonymous]
		[HttpPost("Password.Reset/{identity}")]
		[HttpPost("Password.Reset/{namespace:required}:{identity}")]
		public Task<IActionResult> ResetPassword(string @namespace, string identity, [FromBody]PasswordResetEntity content)
		{
			if(string.IsNullOrWhiteSpace(identity))
				return Task.FromResult((IActionResult)this.BadRequest());

			if(content.PasswordAnswers == null || content.PasswordAnswers.Length < 3)
				Task.FromResult(this.BadRequest());

			return this.UserProvider.ResetPassword(identity, @namespace, content.PasswordAnswers, content.Password) ?
				Task.FromResult((IActionResult)this.NoContent()) :
				Task.FromResult((IActionResult)this.BadRequest());
		}

		[HttpGet("{id}/Password.Questions")]
		[HttpGet("Password.Questions")]
		public Task<IActionResult> GetPasswordQuestions(uint id = 0)
		{
			var result = this.UserProvider.GetPasswordQuestions(id);

			//如果返回的结果为空表示指定的表示的用户不存在
			if(result == null)
				return Task.FromResult((IActionResult)this.NotFound());

			//如果问题数组内容不是全空，则返回该数组
			for(int i = 0; i < result.Length; i++)
			{
				if(!string.IsNullOrEmpty(result[i]))
					return Task.FromResult((IActionResult)this.Ok(result));
			}

			//返回空消息
			return Task.FromResult((IActionResult)this.NoContent());
		}

		[AllowAnonymous]
		[HttpGet("Password.Questions/{identity}")]
		[HttpGet("Password.Questions/{namespace:required}:{identity}")]
		public Task<IActionResult> GetPasswordQuestions(string @namespace, string identity)
		{
			if(string.IsNullOrWhiteSpace(identity))
				return Task.FromResult((IActionResult)this.BadRequest());

			var result = this.UserProvider.GetPasswordQuestions(identity, @namespace);

			//如果返回的结果为空表示指定的表示的用户不存在
			if(result == null)
				return Task.FromResult((IActionResult)this.NotFound());

			//如果问题数组内容不是全空，则返回该数组
			for(int i = 0; i < result.Length; i++)
			{
				if(!string.IsNullOrEmpty(result[i]))
					return Task.FromResult((IActionResult)this.Ok(result));
			}

			//返回空消息
			return Task.FromResult((IActionResult)this.NoContent());
		}

		[HttpPut("{id}/Password.Answers")]
		[HttpPut("Password.Answers")]
		public Task<IActionResult> SetPasswordQuestionsAndAnswers(uint id, [FromBody]PasswordQuestionsAndAnswersEntity content)
		{
			return this.UserProvider.SetPasswordQuestionsAndAnswers(id, content.Password, content.Questions, content.Answers) ?
				Task.FromResult((IActionResult)this.NoContent()) :
				Task.FromResult((IActionResult)this.NotFound());
		}
		#endregion

		#region 成员操作
		[HttpGet("{id}/Ancestors")]
		[HttpGet("Ancestors/{id:required}")]
		public Task<IActionResult> GetAncestors(uint id)
		{
			var roles = this.MemberProvider.GetAncestors(id, MemberType.User);

			return roles != null && roles.Any() ?
				Task.FromResult((IActionResult)this.Ok(roles)) :
				Task.FromResult((IActionResult)this.NoContent());
		}

		[HttpGet("{id}/Roles")]
		[HttpGet("Roles/{id?}")]
		public Task<IActionResult> GetRoles(uint id = 0)
		{
			if(id == 0)
				id = this.User.Identity.GetIdentifier<uint>();

			var roles = this.MemberProvider.GetRoles(id, MemberType.User);

			return roles != null && roles.Any() ?
				Task.FromResult((IActionResult)this.Ok(roles)) :
				Task.FromResult((IActionResult)this.NoContent());
		}

		[HttpPut("{id}/Roles")]
		[HttpPut("Roles/{id}")]
		public async Task<IActionResult> SetRoles(uint id)
		{
			var content = await this.Request.ReadAsStringAsync();

			if(string.IsNullOrWhiteSpace(content))
				return this.BadRequest();

			var members = Zongsoft.Common.StringExtension.Slice<uint>(content, ',', uint.TryParse).Select(roleId => new Member(roleId, id, MemberType.User));
			return this.MemberProvider.SetMembers(members) > 0 ? (IActionResult)this.CreatedAtAction(nameof(GetRoles), new { id }, members) : this.NotFound();
		}

		[HttpGet("{id}/In/{roles:required}")]
		[HttpGet("In/{roles:required}")]
		public Task<IActionResult> InRole(uint id, string roles)
		{
			if(string.IsNullOrWhiteSpace(roles))
				return Task.FromResult((IActionResult)this.BadRequest());

			return this.Authorizer.InRoles(id, Common.StringExtension.Slice(roles, ',', '|').ToArray()) ?
				Task.FromResult((IActionResult)this.NoContent()) :
				Task.FromResult((IActionResult)this.NotFound());
		}
		#endregion

		#region 授权操作
		[HttpGet("{id}/Authorize/{schemaId}:{actionId}")]
		[HttpGet("Authorize/{schemaId}:{actionId}")]
		public Task<IActionResult> Authorize(uint id, string schemaId, string actionId)
		{
			if(string.IsNullOrWhiteSpace(schemaId))
				return Task.FromResult((IActionResult)this.BadRequest("Missing schema for the authorize operation."));
			if(string.IsNullOrWhiteSpace(actionId))
				return Task.FromResult((IActionResult)this.BadRequest("Missing action for the authorize operation."));

			return this.Authorizer.Authorize(id, schemaId, actionId) ?
				Task.FromResult((IActionResult)this.NoContent()) :
				Task.FromResult((IActionResult)this.NotFound());
		}

		[HttpGet("{id}/Authorizes")]
		[HttpGet("Authorizes/{id?}")]
		public IActionResult Authorizes(uint id = 0)
		{
			if(id == 0)
				id = this.User.Identity.GetIdentifier<uint>();

			return this.Ok(this.Authorizer.Authorizes(id, MemberType.User).Select(p =>
				p.Schema + ":" + string.Join(',', p.Actions.Select(a => a.Action).ToArray())
			));
		}
		#endregion

		#region 权限操作
		[HttpGet("{id}/Permissions/{schemaId?}", Name = nameof(GetPermissions))]
		[HttpGet("Permissions/{schemaId?}")]
		public Task<IActionResult> GetPermissions(uint id, string schemaId = null)
		{
			var result = this.PermissionProvider.GetPermissions(id, MemberType.User, schemaId)
				.GroupBy(p => p.SchemaId)
				.ToDictionary(group => group.Key, elements => elements.Select(element => element.ActionId + ":" + element.Granted.ToString()));

			return (result != null && result.Count > 0) ?
				Task.FromResult((IActionResult)this.Ok(result)) :
				Task.FromResult((IActionResult)this.NoContent());
		}

		[HttpPut("{id}/Permissions")]
		[HttpPut("Permissions")]
		public Task<IActionResult> SetPermissions(uint id, [FromBody]IEnumerable<Permission> permissions, [FromQuery]bool reset = false)
		{
			return this.PermissionProvider.SetPermissions(id, MemberType.User, permissions, reset) > 0 ?
				Task.FromResult((IActionResult)this.CreatedAtRoute(nameof(GetPermissions), new { id }, null)) :
				Task.FromResult((IActionResult)this.NoContent());
		}

		[HttpDelete("{id}/Permission/{schemaId}:{actionId}")]
		[HttpDelete("Permission/{schemaId}:{actionId}")]
		public Task<IActionResult> RemovePermission(uint id, string schemaId, string actionId = null)
		{
			if(string.IsNullOrWhiteSpace(schemaId) || string.IsNullOrWhiteSpace(actionId))
				return Task.FromResult((IActionResult)this.BadRequest());

			return this.PermissionProvider.RemovePermissions(id, MemberType.User, schemaId, actionId) > 0 ?
				Task.FromResult((IActionResult)this.NoContent()) :
				Task.FromResult((IActionResult)this.NotFound());
		}

		[HttpDelete("{id}/Permissions/{schemaId?}")]
		[HttpDelete("Permissions/{schemaId?}")]
		public Task<IActionResult> RemovePermissions(uint id, string schemaId = null)
		{
			return this.PermissionProvider.RemovePermissions(id, MemberType.User, schemaId) > 0 ?
				Task.FromResult((IActionResult)this.NoContent()) :
				Task.FromResult((IActionResult)this.NotFound());
		}

		[HttpGet("{id}/Permission.Filters/{schemaId?}", Name = nameof(GetPermissionFilters))]
		[HttpGet("Permission.Filters/{schemaId?}")]
		public Task<IActionResult> GetPermissionFilters(uint id, string schemaId = null)
		{
			var result = this.PermissionProvider.GetPermissionFilters(id, MemberType.User, schemaId)
				.GroupBy(p => p.SchemaId)
				.ToDictionary(group => group.Key, elements => elements.Select(element => element.ActionId + ":" + element.Filter));

			return (result != null && result.Count > 0) ?
				Task.FromResult((IActionResult)this.Ok(result)) :
				Task.FromResult((IActionResult)this.NoContent());
		}

		[HttpPut("{id}/Permission.Filters")]
		[HttpPut("Permission.Filters")]
		public Task<IActionResult> SetPermissionFilters(uint id, [FromBody]IEnumerable<PermissionFilter> permissions, [FromQuery]bool reset = false)
		{
			return this.PermissionProvider.SetPermissionFilters(id, MemberType.User, permissions, reset) > 0 ?
				Task.FromResult((IActionResult)this.CreatedAtRoute(nameof(GetPermissionFilters), new { id }, null)) :
				Task.FromResult((IActionResult)this.NoContent());
		}

		[HttpDelete("{id}/Permission.Filter/{schemaId}:{actionId}")]
		[HttpDelete("Permission.Filter/{schemaId}:{actionId}")]
		public Task<IActionResult> RemovePermissionFilter(uint id, string schemaId, string actionId)
		{
			if(string.IsNullOrEmpty(schemaId) || string.IsNullOrEmpty(actionId))
				return Task.FromResult((IActionResult)this.BadRequest());

			return this.PermissionProvider.RemovePermissionFilters(id, MemberType.User, schemaId, actionId) > 0 ?
				Task.FromResult((IActionResult)this.NoContent()) :
				Task.FromResult((IActionResult)this.NotFound());
		}

		[HttpDelete("{id}/Permission.Filters/{schemaId?}")]
		[HttpDelete("Permission.Filters/{schemaId?}")]
		public Task<IActionResult> RemovePermissionFilters(uint id, string schemaId = null)
		{
			return this.PermissionProvider.RemovePermissionFilters(id, MemberType.User, schemaId) > 0 ?
				Task.FromResult((IActionResult)this.NoContent()) :
				Task.FromResult((IActionResult)this.NotFound());
		}
		#endregion

		#region 内部结构
		public struct RegisterEntity
		{
			public string FullName { get; set; }
			public string Identity { get; set; }
			public string Password { get; set; }
			public string Namespace { get; set; }
			public string Description { get; set; }
			public IDictionary<string, object> Parameters { get; set; }
		}

		public struct PasswordChangeEntity
		{
			public string OldPassword { get; set; }
			public string NewPassword { get; set; }
		}

		public struct PasswordResetEntity
		{
			public string Secret { get; set; }
			public string Password { get; set; }
			public string[] PasswordAnswers { get; set; }
		}

		public struct PasswordQuestionsAndAnswersEntity
		{
			public string Password { get; set; }
			public string[] Questions { get; set; }
			public string[] Answers { get; set; }
		}
		#endregion
	}

	[ApiController]
	[Area(Modules.Security)]
	[Route("{area}/Users/Verification")]
	public class UserVerifierController : ControllerBase
	{
		private IUserProvider<IUser> _userProvider;

		[ServiceDependency(IsRequired = true)]
		public IUserProvider<IUser> UserProvider
		{
			get => _userProvider;
			set => _userProvider = value ?? throw new ArgumentNullException();
		}

		[HttpPost("Issue/{verifier}:{key}")]
		[HttpPost("Issue/{verifier}:{key}!{namespace:required}")]
		public Task<IActionResult> Issue(string verifier, string key, string @namespace)
		{
			if(string.IsNullOrWhiteSpace(key))
				return Task.FromResult((IActionResult)this.BadRequest());

			if(!string.IsNullOrWhiteSpace(@namespace))
				key = key + "!" + @namespace;

			_userProvider.Verification.GetVerifier(verifier).Issue(key);
			return Task.FromResult((IActionResult)this.NoContent());
		}

		[HttpPost("Verify/{verifier}:{key}")]
		[HttpPost("Verify/{verifier}:{key}!{namespace:required}")]
		public async Task<IActionResult> Verify(string verifier, string key, string @namespace)
		{
			var token = await this.Request.ReadAsStringAsync();

			if(!string.IsNullOrWhiteSpace(@namespace))
				key = key + "!" + @namespace;

			if(_userProvider.Verification.GetVerifier(verifier).Verify(key, token))
				return this.NoContent();

			return this.NotFound();
		}
	}
}
