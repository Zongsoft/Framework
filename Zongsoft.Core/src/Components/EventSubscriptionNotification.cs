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
 * Copyright (C) 2010-2023 Zongsoft Studio <http://www.zongsoft.com>
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
using System.Threading;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Zongsoft.Components
{
	public class EventSubscriptionNotificationCollection : KeyedCollection<string, IEventSubscriptionNotification>, IAsyncEnumerable<IEventSubscriptionNotification>
	{
		public EventSubscriptionNotificationCollection() : base(StringComparer.OrdinalIgnoreCase, 3) { }

		public async IAsyncEnumerator<IEventSubscriptionNotification> GetAsyncEnumerator(CancellationToken cancellationToken = default)
		{
			IEventSubscriptionNotification n = null;

			System.Data.Common.DbCommand command = null;
			var reader = await command.ExecuteReaderAsync(cancellationToken);
			while(await reader.ReadAsync(cancellationToken))
			{
				yield return Zongsoft.Data.Model.Build<IEventSubscriptionNotification>(notification =>
				{
				});
			}

			yield return n;
		}

		protected override string GetKeyForItem(IEventSubscriptionNotification item) => $"{item.Notifier}:{item.Channel}";
	}
}
