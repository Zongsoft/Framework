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
 * Copyright (C) 2010-2022 Zongsoft Studio <http://www.zongsoft.com>
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

namespace Zongsoft.Scheduling
{
	public class TriggerOptions : ITriggerOptions
	{
		#region 构造函数
		public TriggerOptions(string id = null) => this.Identifier = id;
		#endregion

		#region 公共属性
		public string Identifier { get; set; }
		#endregion

		#region 嵌套子类
		public class Cron : TriggerOptions
		{
			public Cron(string expression) => this.Expression = expression;
			public Cron(string id, string expression) : base(id) => this.Expression = expression;

			public string Expression { get; set; }
		}

		public class Latency : TriggerOptions
		{
			public Latency(TimeSpan duration) => this.Duration = duration;
			public Latency(string id, TimeSpan duration) : base(id) => this.Duration = duration;

			public TimeSpan Duration { get; set; }
		}
		#endregion
	}
}