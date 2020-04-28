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
using System.Security.Claims;
using System.Security.Principal;

namespace Zongsoft.Security
{
	internal static class Anonymous
	{
		public static readonly ClaimsPrincipal Principal = new AnonymousPrincipal();
		public static readonly IIdentity Identity = new AnonymousIdentity();

		public static bool IsAnonymous(this IPrincipal principal)
		{
			return principal == null || principal is AnonymousPrincipal;
		}

		public static bool IsAnonymous(this IIdentity identity)
		{
			return identity == null || identity is AnonymousIdentity;
		}

		private class AnonymousPrincipal : ClaimsPrincipal
		{
			public AnonymousPrincipal() : base(Anonymous.Identity)
			{
			}
		}

		private class AnonymousIdentity : IIdentity
		{
			public AnonymousIdentity()
			{
			}

			public string AuthenticationType => string.Empty;
			public bool IsAuthenticated => false;
			public string Name => string.Empty;
		}
	}
}