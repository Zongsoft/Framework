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
 * This file is part of Zongsoft.Net library.
 *
 * The Zongsoft.Net is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3.0 of the License,
 * or (at your option) any later version.
 *
 * The Zongsoft.Net is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the Zongsoft.Net library. If not, see <http://www.gnu.org/licenses/>.
 */

using System;

using Zongsoft.Services;
using Zongsoft.Components;

namespace Zongsoft.Net.Commands
{
	public class TcpServerInfoCommand : Services.Commands.WorkerInfoCommand
	{
		#region 构造函数
		public TcpServerInfoCommand() { }
		public TcpServerInfoCommand(string name) : base(name) { }
		#endregion

		#region 重写方法
		protected override void Info(CommandContext context, IWorker worker)
		{
			//通过基类方法打印基本信息
			base.Info(context, worker);

			if(worker is TcpServer<string> server)
			{
				var index = 0;

				foreach(var channel in server.Channels)
				{
					var content = CommandOutletContent
					.Create(CommandOutletColor.DarkMagenta, $"#{++index} ")
					.Append(CommandOutletColor.DarkYellow, $"[{channel.Address}]")
					.Append(CommandOutletColor.DarkGray, "(")
					.Append(CommandOutletColor.DarkGreen, channel.TotalBytesSent.ToString())
					.Append(CommandOutletColor.DarkGray, " | ")
					.Append(CommandOutletColor.DarkGreen, channel.TotalBytesReceived.ToString())
					.Append(CommandOutletColor.DarkGray, ")");

					context.Output.WriteLine(content);
				}
			}
		}
		#endregion
	}
}