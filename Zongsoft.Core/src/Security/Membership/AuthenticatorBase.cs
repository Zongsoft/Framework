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
using System.Linq;
using System.Security.Claims;
using System.Collections.Generic;

using Zongsoft.Data;
using Zongsoft.Services;

namespace Zongsoft.Security.Membership
{
	public abstract class AuthenticatorBase : IAuthenticator
	{
		#region 常量定义
		private const string KEY_AUTHENTICATION_SECRET = "Zongsoft.Security.Authentication";
		private const string KEY_AUTHENTICATION_TEMPLATE = "Authentication";
		#endregion

		#region 事件声明
		public event EventHandler<AuthenticatedEventArgs> Authenticated;
		public event EventHandler<AuthenticatingEventArgs> Authenticating;
		#endregion

		#region 构造函数
		protected AuthenticatorBase(IServiceProvider serviceProvider)
		{
			this.ServiceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
			this.DataAccess = serviceProvider.ResolveRequired<IDataAccessProvider>()
				.GetAccessor(Mapping.Security) ?? serviceProvider.GetDataAccess(true);
		}
		#endregion

		#region 公共属性
		public virtual string Scheme { get => "Zongsoft.Authentication"; }

		[ServiceDependency]
		public IAttempter Attempter { get; set; }
		public IDataAccess DataAccess { get; protected set; }
		public IServiceProvider ServiceProvider { get; }
		#endregion

		#region 公共方法
		public bool Verify(uint userId, string password, out string reason)
		{
			//获取验证失败的解决器
			var attempter = this.Attempter;

			//确认验证失败是否超出限制数，如果超出则返回账号被禁用
			if(attempter != null && !attempter.Verify(userId.ToString()))
			{
				reason = SecurityReasons.AccountSuspended;
				return false;
			}

			var token = this.DataAccess.Select<UserSecret>(Mapping.Instance.User, Condition.Equal(nameof(IUser.UserId), userId)).FirstOrDefault();

			//如果帐户不存在则返回无效账户
			if(token.UserId == 0)
			{
				reason = SecurityReasons.InvalidIdentity;
				return false;
			}

			//如果账户状态异常则返回账户状态异常
			if(token.Status != UserStatus.Active)
			{
				reason = SecurityReasons.AccountDisabled;
				return false;
			}

			if(!PasswordUtility.VerifyPassword(password, token.Password, token.PasswordSalt, "SHA1"))
			{
				//通知验证尝试失败
				if(attempter != null)
					attempter.Fail(userId.ToString());

				//密码校验失败则返回密码验证失败
				reason = SecurityReasons.InvalidPassword;
				return false;
			}

			//通知验证尝试成功，即清空验证失败记录
			if(attempter != null)
				attempter.Done(userId.ToString());

			//返回校验成功
			reason = null;
			return true;
		}

		public AuthenticationResult Authenticate(string identity, string password, string @namespace, string scenario, IDictionary<string, object> parameters)
		{
			if(string.IsNullOrWhiteSpace(identity))
				throw new ArgumentNullException(nameof(identity));

			//激发“Authenticating”事件
			this.OnAuthenticating(@namespace, identity, scenario, parameters);

			//获取验证失败的解决器
			var attempter = this.Attempter;

			//确认验证失败是否超出限制数，如果超出则返回账号被禁用
			if(attempter != null && !attempter.Verify(identity, @namespace))
				return AuthenticationResult.Fail(SecurityReasons.AccountSuspended);

			//获取当前用户的密码及密码盐
			var userId = this.GetPassword(identity, @namespace, out var storedPassword, out var storedPasswordSalt, out var status, out _);

			//如果帐户不存在则返回无效账户
			if(userId == 0)
				return AuthenticationResult.Fail(SecurityReasons.InvalidIdentity);

			//如果账户状态异常则返回账户状态异常
			if(status != UserStatus.Active)
				return AuthenticationResult.Fail(SecurityReasons.AccountDisabled);

			if(!PasswordUtility.VerifyPassword(password, storedPassword, storedPasswordSalt, "SHA1"))
			{
				//通知验证尝试失败
				if(attempter != null)
					attempter.Fail(identity, @namespace);

				//密码校验失败则返回密码验证失败
				return AuthenticationResult.Fail(SecurityReasons.InvalidPassword);
			}

			//通知验证尝试成功，即清空验证失败记录
			if(attempter != null)
				attempter.Done(identity, @namespace);

			//获取指定用户编号对应的用户对象
			var user = this.DataAccess.Select<IUser>(Mapping.Instance.User, Condition.Equal(nameof(IUser.UserId), userId)).FirstOrDefault();

			//激发“Authenticated”事件
			return this.OnAuthenticated(user, parameters);
		}

		public AuthenticationResult Authenticate(string identity, string verifier, string token, string @namespace, string scenario, IDictionary<string, object> parameters)
		{
			if(string.IsNullOrWhiteSpace(identity))
				throw new ArgumentNullException(nameof(identity));

			//激发“Authenticating”事件
			this.OnAuthenticating(@namespace, identity, scenario, parameters);

			//获取验证失败的解决器
			var attempter = this.Attempter;

			//确认验证失败是否超出限制数，如果超出则返回账号被禁用
			if(attempter != null && !attempter.Verify(identity, @namespace))
				return AuthenticationResult.Fail(SecurityReasons.AccountSuspended);

			//获取指定标识的用户对象
			var user = this.DataAccess.Select<IUser>(MembershipUtility.GetIdentityCondition(identity, out _) & this.GetNamespace(@namespace)).FirstOrDefault();

			//如果帐户不存在则返回无效账号
			if(user == null)
				return AuthenticationResult.Fail(SecurityReasons.InvalidIdentity);

			//如果账户状态异常则返回账号状态异常
			if(user.Status != UserStatus.Active)
				return AuthenticationResult.Fail(SecurityReasons.AccountDisabled);

			//获取必须的校验器
			var authority = this.ServiceProvider.ResolveRequired<IIdentityVerifierProvider>().GetVerifier(verifier) ?? throw new InvalidOperationException("Missing the required authority.");

			if(!authority.Verify(identity, token, parameters))
			{
				//通知验证尝试失败
				if(attempter != null)
					attempter.Fail(identity, @namespace);

				//验证码校验失败则返回校验失败
				return AuthenticationResult.Fail(SecurityReasons.VerifyFaild);
			}

			//通知验证尝试成功，即清空验证失败记录
			if(attempter != null)
				attempter.Done(identity, @namespace);

			//激发“Authenticated”事件
			return this.OnAuthenticated(user, parameters);
		}

		public AuthenticationResult AuthenticateSecret(string identity, string secret, string @namespace, string scenario, IDictionary<string, object> parameters)
		{
			if(string.IsNullOrWhiteSpace(identity))
				throw new ArgumentNullException(nameof(identity));

			//激发“Authenticating”事件
			this.OnAuthenticating(@namespace, identity, scenario, parameters);

			//获取验证失败的解决器
			var attempter = this.Attempter;

			//确认验证失败是否超出限制数，如果超出则返回账号被禁用
			if(attempter != null && !attempter.Verify(identity, @namespace))
				return AuthenticationResult.Fail(SecurityReasons.AccountSuspended);

			//获取指定标识的用户对象
			var user = this.DataAccess.Select<IUser>(MembershipUtility.GetIdentityCondition(identity, out _) & this.GetNamespace(@namespace)).FirstOrDefault();

			//如果帐户不存在则返回无效账号
			if(user == null)
				return AuthenticationResult.Fail(SecurityReasons.InvalidIdentity);

			//如果账户状态异常则返回账号状态异常
			if(user.Status != UserStatus.Active)
				return AuthenticationResult.Fail(SecurityReasons.AccountDisabled);

			//获取必须的秘密生成器
			var secretor = this.GetSecretor() ?? throw new InvalidOperationException($"Missing a required secretor.");

			if(!secretor.Verify(GetSecretKey(identity, @namespace), secret))
			{
				//通知验证尝试失败
				if(attempter != null)
					attempter.Fail(identity, @namespace);

				//验证码校验失败则返回密码验证失败
				return AuthenticationResult.Fail(SecurityReasons.InvalidPassword);
			}

			//通知验证尝试成功，即清空验证失败记录
			if(attempter != null)
				attempter.Done(identity, @namespace);

			//激发“Authenticated”事件
			return this.OnAuthenticated(user, parameters);
		}
		#endregion

		#region 获取秘密
		public void Secret(string identity, string @namespace = null)
		{
			//获取必须的秘密生成器
			var secretor = this.GetSecretor() ?? throw new InvalidOperationException($"Missing a required secretor.");
			var secret = secretor.Generate(GetSecretKey(identity, @namespace));

			switch(MembershipUtility.GetIdentityType(identity))
			{
				case UserIdentityType.Email:
					CommandExecutor.Default.Execute($"email.send -template:{KEY_AUTHENTICATION_TEMPLATE} {identity}", new
					{
						Code = secret,
					});
					break;
				case UserIdentityType.Phone:
					CommandExecutor.Default.Execute($"phone.send -template:{KEY_AUTHENTICATION_TEMPLATE} {identity}", new
					{
						Code = secret,
					});
					break;
				default:
					throw new ArgumentException($"Invalid secret code identity.");
			}
		}
		#endregion

		#region 虚拟方法
		protected abstract ISecretor GetSecretor();
		protected virtual uint GetPassword(string identity, string @namespace, out byte[] password, out long passwordSalt, out UserStatus status, out DateTime? statusTimestamp)
		{
			if(string.IsNullOrWhiteSpace(@namespace))
				@namespace = null;

			var token = this.DataAccess.Select<UserSecret>(Mapping.Instance.User,
				MembershipUtility.GetIdentityCondition(identity) & this.GetNamespace(@namespace)).FirstOrDefault();

			if(token.UserId == 0)
			{
				password = null;
				passwordSalt = 0;
				status = UserStatus.Active;
				statusTimestamp = null;
			}
			else
			{
				password = token.Password;
				passwordSalt = token.PasswordSalt;
				status = token.Status;
				statusTimestamp = token.StatusTimestamp;
			}

			return token.UserId;
		}
		#endregion

		#region 质询完成
		protected virtual void OnChallenged(AuthenticationContext context) { }
		void IAuthenticator.OnChallenged(AuthenticationContext context) => this.OnChallenged(context);
		#endregion

		#region 激发事件
		private AuthenticationResult OnAuthenticated(IUser user, IDictionary<string, object> parameters)
		{
			var identity = this.Identity(user);
			this.OnAuthenticated(identity, parameters);
			return AuthenticationResult.Success(identity);
		}

		protected virtual void OnAuthenticated(ClaimsIdentity identity, IDictionary<string, object> parameters)
		{
			this.Authenticated?.Invoke(this, new AuthenticatedEventArgs(this, identity, parameters));
		}

		protected virtual void OnAuthenticating(string @namespace, string identity, string scenario, IDictionary<string, object> parameters)
		{
			this.Authenticating?.Invoke(this, new AuthenticatingEventArgs(this, @namespace, identity, scenario, parameters));
		}
		#endregion

		#region 私有方法
		[System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
		private string GetSecretKey(string identity, string @namespace)
		{
			return KEY_AUTHENTICATION_SECRET + ":" +
				(
					string.IsNullOrWhiteSpace(@namespace) ?
					identity.Trim() :
					identity.Trim() + "!" + @namespace.Trim()
				).ToLowerInvariant();
		}

		[System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
		private Condition GetNamespace(string @namespace)
		{
			return Mapping.Instance.Namespace.GetCondition(Mapping.Instance.User, @namespace);
		}
		#endregion

		#region 嵌套结构
		private struct UserSecret
		{
			public uint UserId;
			public byte[] Password;
			public long PasswordSalt;
			public UserStatus Status;
			public DateTime? StatusTimestamp;
		}
		#endregion
	}
}
