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
 * This file is part of Zongsoft.Plugins library.
 *
 * The Zongsoft.Plugins is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3.0 of the License,
 * or (at your option) any later version.
 *
 * The Zongsoft.Plugins is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the Zongsoft.Plugins library. If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Threading.Tasks;

using Zongsoft.Plugins;
using Zongsoft.Services;

namespace Zongsoft.Terminals
{
	public class Workbench : WorkbenchBase
	{
		#region 成员字段
		private TerminalCommandExecutor _executor;
		#endregion

		#region 构造函数
		public Workbench(PluginApplicationContext applicationContext) : base(applicationContext)
		{
		}
		#endregion

		#region 公共属性
		public TerminalCommandExecutor Executor
		{
			get => _executor ?? CommandExecutor.Default as TerminalCommandExecutor;
			set => _executor = value;
		}
		#endregion

		#region 打开方法
		protected override void OnOpen()
		{
			var executor = this.Executor ?? throw new InvalidOperationException("Missing the required command executor of the terminal.");

			//调用基类同名方法
			base.OnOpen();

			//激发“Opened”事件
			this.RaiseOpened();

			//启动命令运行器
			executor.Run();

			//关闭命令执行器
			//注意：因为基类中的线程同步锁独占机制，因此不能由“开启临界区”直接跳入“关闭临界区”
			Task.Delay(100).ContinueWith(task => this.Close());
		}
		#endregion
	}
}
