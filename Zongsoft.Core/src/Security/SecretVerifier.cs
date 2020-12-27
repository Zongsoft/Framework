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

using Zongsoft.Common;
using Zongsoft.Services;
using Zongsoft.Collections;

namespace Zongsoft.Security
{
	[Service(typeof(IIdentityVerifier))]
	public class SecretVerifier : IIdentityVerifier, IMatchable<string>
	{
		#region 构造函数
		public SecretVerifier() { }
		#endregion

		#region 公共属性
		public string Name => "Secret";

		[ServiceDependency]
		public ISecretor Secretor { get; set; }
		#endregion

		#region 公共方法
		public string Issue(string identity, IDictionary<string, object> parameters = null)
		{
			var token = Environment.TickCount64.ToString("X") + Randomizer.GenerateString();
			var secret = this.Secretor.Generate(GetKey(token), identity);

			if(identity.Contains('@'))
				return this.IssueEmail(identity, this.GetTemplate(parameters), secret, parameters) ? token : null;
			else
				return this.IssuePhone(identity, this.GetTemplate(parameters), secret, parameters) ? token : null;
		}

		public bool Verify(string token, out string identity, IDictionary<string, object> parameters = null)
		{
			if(string.IsNullOrWhiteSpace(token))
				throw new ArgumentNullException(nameof(token));

			var index = token.IndexOfAny(new[] { ':', '=' });

			if(index > 0 && index < token.Length - 1)
			{
				var key = token.Substring(0, index);
				var secret = token.Substring(index + 1);

				return this.Secretor.Verify(GetKey(key), secret, out identity);
			}

			identity = null;
			return false;
		}

		public bool Verify(string token, string secret, out string identity, IDictionary<string, object> parameters = null)
		{
			if(string.IsNullOrWhiteSpace(token))
				throw new ArgumentNullException(nameof(token));

			return this.Secretor.Verify(GetKey(token), secret, out identity);
		}
		#endregion

		#region 虚拟方法
		protected virtual string GetTemplate(IDictionary<string, object> parameters)
		{
			if(parameters != null && parameters.TryGetValue("template", out var value) && value is string text)
				return text;

			throw new InvalidOperationException($"Missing the required template parameter.");
		}

		protected virtual bool IssueEmail(string identity, string template, string secret, IDictionary<string, object> parameters)
		{
			try
			{
				CommandExecutor.Default.Execute($"email.send -template:{template} {identity}", new
				{
					Code = secret,
					Data = parameters,
				});

				return true;
			}
			catch(Exception ex)
			{
				Zongsoft.Diagnostics.Logger.Error(ex);
				return false;
			}
		}

		protected virtual bool IssuePhone(string key, string template, string secret, IDictionary<string, object> parameters)
		{
			try
			{
				if(parameters != null &&
				   parameters.TryGetValue("channel", out var value) &&
				   value is string text &&
				   string.Equals(text, "voice", StringComparison.OrdinalIgnoreCase))
					CommandExecutor.Default.Execute($"phone.call -template:{template} {key}", new
					{
						Code = secret,
						Data = parameters,
					});
				else
					CommandExecutor.Default.Execute($"phone.send -template:{template} {key}", new
					{
						Code = secret,
						Data = parameters,
					});

				return true;
			}
			catch(Exception ex)
			{
				Zongsoft.Diagnostics.Logger.Error(ex);
				return false;
			}
		}
		#endregion

		#region 私有方法
		private static string GetKey(string token) => "Zongsoft.SecretVerifier:" + token;
		#endregion

		#region 匹配方法
		bool IMatchable<string>.Match(string parameter) => this.Name.Equals(parameter, StringComparison.OrdinalIgnoreCase);
		bool IMatchable.Match(object parameter) => this.Name.Equals(parameter as string, StringComparison.OrdinalIgnoreCase);
		#endregion
	}
}
