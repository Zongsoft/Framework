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
using System.Linq;
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
		public IdentityVerifierResult Issue(string key, IDictionary<string, object> parameters = null)
		{
			var secret = this.Secretor.Generate(this.GetSecretKey(key, parameters));

			if(key.Contains('@'))
				return this.IssueEmail(key, this.GetTemplate(parameters), secret, parameters);
			else
				return this.IssuePhone(key, this.GetTemplate(parameters), secret, parameters);
		}

		public bool Verify(string key, string token, IDictionary<string, object> parameters = null)
		{
			if(string.IsNullOrWhiteSpace(key))
				throw new ArgumentNullException(nameof(key));

			return this.Secretor.Verify(this.GetSecretKey(key, parameters), token, out _);
		}
		#endregion

		#region 虚拟方法
		protected virtual string GetTemplate(IDictionary<string, object> parameters)
		{
			if(parameters != null && parameters.TryGetValue("template", out var value) && value is string text)
				return text;

			throw new InvalidOperationException($"Missing the required template parameter.");
		}

		protected virtual string GetSecretKey(string key, IDictionary<string, object> parameters)
		{
			if(parameters != null && parameters.TryGetValue("namespace", out var value) && value is string text && !string.IsNullOrWhiteSpace(text))
				return $"{text.Trim()}.{this.Name}:{key}";

			return $"{this.Name}:{key}";
		}

		protected virtual IdentityVerifierResult IssueEmail(string key, string template, string secret, IDictionary<string, object> parameters)
		{
			try
			{
				CommandExecutor.Default.Execute($"email.send -template:{template} {key}", new
				{
					Code = secret,
					Data = parameters,
				});

				return IdentityVerifierResult.Success(key, secret, parameters);
			}
			catch(Exception ex)
			{
				return IdentityVerifierResult.Fail(key, ex, parameters);
			}
		}

		protected virtual IdentityVerifierResult IssuePhone(string key, string template, string secret, IDictionary<string, object> parameters)
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

				return IdentityVerifierResult.Success(key, secret, parameters);
			}
			catch(Exception ex)
			{
				return IdentityVerifierResult.Fail(key, ex, parameters);
			}
		}
		#endregion

		#region 私有方法
		private IEnumerable<KeyValuePair<string, string>> ResolveExtra(string extra)
		{
			return extra.Slice(';').Select(pair =>
			{
				var index = pair.IndexOfAny(new[] { '=', ':' });

				if(index < 0)
					return new KeyValuePair<string, string>(pair, null);
				else if(index == 0)
					return new KeyValuePair<string, string>(string.Empty, pair.Substring(1));
				else if(index == pair.Length - 1)
					return new KeyValuePair<string, string>(pair.Substring(0, index), null);
				else
					return new KeyValuePair<string, string>(pair.Substring(0, index), pair.Substring(index + 1));
			});
		}
		#endregion

		#region 匹配方法
		bool IMatchable<string>.Match(string parameter) => this.Name.Equals(parameter, StringComparison.OrdinalIgnoreCase);
		bool IMatchable.Match(object parameter) => this.Name.Equals(parameter as string, StringComparison.OrdinalIgnoreCase);
		#endregion
	}
}
