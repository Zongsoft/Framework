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
 * This file is part of Zongsoft.Scheduling library.
 *
 * The Zongsoft.Scheduling is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3.0 of the License,
 * or (at your option) any later version.
 *
 * The Zongsoft.Scheduling is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the Zongsoft.Scheduling library. If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;

namespace Zongsoft.Scheduling
{
	public abstract class Scheduler<TKey, TData> : Scheduler where TKey : struct, IEquatable<TKey> where TData : class
	{
		#region 成员字段
		private readonly ConcurrentDictionary<TKey, long> _mapping;
		#endregion

		#region 构造函数
		protected Scheduler(string name = null) : base(name)
		{
			_mapping = new ConcurrentDictionary<TKey, long>();
		}
		#endregion

		#region 公共方法
		public ScheduleToken GetSchedule(TKey key)
		{
			return _mapping.TryGetValue(key, out var scheduleId) ? this.GetSchedule(scheduleId) : null;
		}

		public long Schedule(TKey key)
		{
			var data = this.GetData(key);

			if(data == null)
			{
				if(_mapping.TryGetValue(key, out var scheduleId) && this.Unschedule(scheduleId))
					return scheduleId;

				return 0;
			}

			return this.Schedule(key, data);
		}

		public bool Unschedule(TKey key)
		{
			if(_mapping.TryGetValue(key, out var scheduleId))
				return this.Unschedule(scheduleId);

			return false;
		}

		protected override long OnSchedule<Token>(Token token)
		{
			if(token is TKey key)
				return this.Schedule(key);

			throw new NotSupportedException();
		}

		protected override bool OnUnschedule<Token>(Token token)
		{
			if(token is TKey key)
				return this.Unschedule(key);

			throw new NotSupportedException();
		}
		#endregion

		#region 调度实现
		private long Schedule(TKey key, TData data)
		{
			if(data == null)
				return 0;

			var state = new ScheduleState(data);

			var scheduleId = _mapping.GetOrAdd(key,
				(_, state) => state.Id = this.Schedule(this.GetHandler(state.Data), this.GetTrigger(state.Data), state.Data),
				state);

			//如果新增的调度失败，则需要将失败的调度项删除
			if(scheduleId == 0)
			{
				if(_mapping.TryRemove(key, out var id) && id != 0)
					_mapping.TryAdd(key, id);
			}

			//如果上面的新增调度成功，则返回该新增的调度项编号
			if(state.Id > 0)
				return scheduleId;

			return this.Reschedule(scheduleId, this.GetTrigger(data), data) ? scheduleId : 0;
		}
		#endregion

		#region 初始方法
		protected virtual void Initialize(IEnumerable<KeyValuePair<TKey, TData>> schedulars)
		{
			if(schedulars == null)
				return;

			foreach(var schedular in schedulars)
			{
				if(schedular.Value != null)
					this.Schedule(schedular.Key, schedular.Value);
			}
		}
		#endregion

		#region 重写方法
		protected override Task OnStartAsync(string[] args, CancellationToken cancellation)
		{
			//初始化调度记录
			this.Initialize(null);

			//调用基类同名方法
			return base.OnStartAsync(args, cancellation);
		}

		protected override Task OnStopAsync(string[] args, CancellationToken cancellation)
		{
			//清空所有调度数据
			this.Unschedule();

			//调用基类同名方法
			return base.OnStopAsync(args, cancellation);
		}
		#endregion

		#region 抽象方法
		protected abstract ITrigger GetTrigger(TData data);
		protected abstract IHandler GetHandler(TData data);
		protected abstract TData GetData(TKey key);
		#endregion

		#region 嵌套子类
		private class ScheduleState
		{
			public ScheduleState(TData data)
			{
				this.Data = data;
			}

			public long Id;
			public readonly TData Data;
		}
		#endregion
	}
}
