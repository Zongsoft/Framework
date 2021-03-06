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
using System.Collections.Generic;

namespace Zongsoft.Collections
{
	[AttributeUsage(AttributeTargets.Class)]
	public class MatcherAttribute : Attribute
	{
		#region 构造函数
		public MatcherAttribute(Type type)
		{
			if(type == null)
				throw new ArgumentNullException(nameof(type));

			if(!typeof(IMatcher).IsAssignableFrom(type))
				throw new ArgumentException("The type is not a IMatcher.");

			this.MatcherType = type;
		}

		public MatcherAttribute(string typeName)
		{
			if(string.IsNullOrWhiteSpace(typeName))
				throw new ArgumentNullException(nameof(typeName));

			var type = Type.GetType(typeName, false);

			if(type == null || !typeof(IMatcher).IsAssignableFrom(type))
				throw new ArgumentException("The type is not a IMatcher.");

			this.MatcherType = type;
		}
		#endregion

		#region 公共属性
		public Type MatcherType { get; }
		#endregion
	}
}
