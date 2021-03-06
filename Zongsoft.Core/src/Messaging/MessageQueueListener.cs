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
using System.IO;
using System.ComponentModel;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;

namespace Zongsoft.Messaging
{
	[DisplayName("${Text.MessageQueueListener.Title}")]
	[Description("${Text.MessageQueueListener.Description}")]
	public class MessageQueueListener : Zongsoft.Communication.ListenerBase
	{
		#region 成员字段
		private Zongsoft.Collections.IQueue _queue;
		#endregion

		#region 构造函数
		public MessageQueueListener(string name) : base(name)
		{
		}

		public MessageQueueListener(Zongsoft.Collections.IQueue queue) : base(nameof(MessageQueueListener))
		{
			_queue = queue ?? throw new ArgumentNullException(nameof(queue));

			if(queue.Name != null && queue.Name.Length > 0)
				base.Name = queue.Name;
		}
		#endregion

		#region 公共属性
		[TypeConverter(typeof(QueueConverter))]
		public Zongsoft.Collections.IQueue Queue
		{
			get
			{
				return _queue;
			}
			set
			{
				if(this.State == Services.WorkerState.Running)
					throw new InvalidOperationException();

				_queue = value ?? throw new ArgumentNullException();
			}
		}
		#endregion

		#region 重写方法
		protected override Communication.IReceiver CreateReceiver()
		{
			return new MessageQueueChannel(1,
				this.Queue ?? throw new InvalidOperationException("Missing the 'Queue' for the operation."));
		}

		protected override void OnStart(string[] args)
		{
			((MessageQueueChannel)this.Receiver).ReceiveAsync();
		}

		protected override void OnStop(string[] args)
		{
			var receiver = this.Receiver;

			if(receiver != null)
			{
				this.Receiver = null;

				if(receiver is IDisposable disposable)
					disposable.Dispose();
			}
		}
		#endregion

		#region 嵌套子类
		private class MessageQueueChannel : Zongsoft.Communication.ChannelBase
		{
			#region 私有变量
			private CancellationTokenSource _cancellation;
			#endregion

			#region 构造函数
			public MessageQueueChannel(int channelId, Zongsoft.Collections.IQueue queue) : base(channelId, queue)
			{
				_cancellation = new CancellationTokenSource();
			}
			#endregion

			#region 公共属性
			public override bool IsIdled
			{
				get
				{
					var cancellation = _cancellation;
					return cancellation != null && !cancellation.IsCancellationRequested;
				}
			}
			#endregion

			#region 收取消息
			public void ReceiveAsync()
			{
				var cancellation = _cancellation;

				if(cancellation == null || cancellation.IsCancellationRequested)
					return;

				Task.Factory.StartNew(this.OnReceive, cancellation.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);
			}

			private void OnReceive()
			{
				var queue = (Zongsoft.Collections.IQueue)this.Host;

				if(queue == null)
					return;

				var cancellation = _cancellation;
				object message = null;

				while(!cancellation.IsCancellationRequested)
				{
					try
					{
						//以同步方式从消息队列中获取一条消息
						message = queue.Dequeue(new MessageDequeueSettings(TimeSpan.FromSeconds(10)));
					}
					catch
					{
						message = null;
					}

					//如果消息获取失败则休息一小会
					if(message == null)
						Thread.Sleep(500);
					else //以异步方式激发消息接收事件
						Task.Run(() =>
						{
							try
							{
								this.OnReceived(message);
							}
							catch { }
						}, cancellation.Token);
				}
			}
			#endregion

			#region 发送方法
			public override void Send(Stream stream, object asyncState = null)
			{
				var queue = (Zongsoft.Collections.IQueue)this.Host;

				if(queue == null || _cancellation.IsCancellationRequested)
					return;

				queue.EnqueueAsync(stream).ContinueWith(_ =>
				{
					this.OnSent(asyncState);
				});
			}

			public override void Send(byte[] buffer, int offset, int count, object asyncState = null)
			{
				var queue = (Zongsoft.Collections.IQueue)this.Host;

				if(queue == null || _cancellation.IsCancellationRequested)
					return;

				if(buffer == null)
					throw new ArgumentNullException(nameof(buffer));

				if(offset < 0 || offset >= buffer.Length - 1)
					throw new ArgumentOutOfRangeException(nameof(offset));

				if(count < 0 || count > buffer.Length - offset)
					throw new ArgumentOutOfRangeException(nameof(count));

				var data = new byte[count];
				Array.Copy(buffer, offset, data, 0, count);

				queue.EnqueueAsync(data).ContinueWith(_ =>
				{
					this.OnSent(asyncState);
				});
			}
			#endregion

			#region 关闭处理
			protected override void OnClose()
			{
				var cancellation = Interlocked.Exchange(ref _cancellation, null);

				if(cancellation != null)
					cancellation.Cancel();
			}
			#endregion
		}

		private class QueueConverter : TypeConverter
		{
			public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType)
			{
				return sourceType == typeof(string) || base.CanConvertFrom(context, sourceType);
			}

			public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value)
			{
				if(value is string name)
				{
					var queueProvider = (Collections.IQueueProvider)Services.ApplicationContext.Current?.Services?.GetService(typeof(Collections.IQueueProvider));

					if(queueProvider != null)
						return queueProvider.GetQueue(name);
				}

				return base.ConvertFrom(context, culture, value);
			}
		}
		#endregion
	}
}
