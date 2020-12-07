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
 * This file is part of Zongsoft.Security library.
 *
 * The Zongsoft.Security is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3.0 of the License,
 * or (at your option) any later version.
 *
 * The Zongsoft.Security is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the Zongsoft.Security library. If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Linq;
using System.Collections.Generic;

using Zongsoft.Data;
using Zongsoft.Services;

namespace Zongsoft.Security.Membership
{
	[Service(typeof(IMemberProvider))]
	public class MemberProvider : IMemberProvider
	{
		#region 构造函数
		public MemberProvider(string name, IServiceProvider serviceProvider)
		{
			this.DataAccess = serviceProvider.ResolveRequired<IDataAccessProvider>()
				.GetAccessor("Security") ?? serviceProvider.GetDataAccess(true);

			if(!string.IsNullOrEmpty(name))
				this.DataAccess.Naming.Map<Member>(name);
		}
		#endregion

		#region 公共属性
		public IDataAccess DataAccess { get; }
		#endregion

		#region 公共方法
		public IEnumerable<IRole> GetRoles(uint memberId, MemberType memberType)
		{
			return this.DataAccess.Select<Member>(
				Condition.Equal(nameof(Member.MemberId), memberId) & Condition.Equal(nameof(Member.MemberType), memberType),
				"*, Role{*}").Map(p => p.Role);
		}

		public IEnumerable<Member> GetMembers(uint roleId, string schema = null)
		{
			return this.DataAccess.Select<Member>(Condition.Equal(nameof(Member.RoleId), roleId), schema);
		}

		public bool SetMember(Member member)
		{
			if(member.RoleId == 0 || member.MemberId == 0)
				return false;

			return this.DataAccess.Upsert(member) > 0;
		}

		public int SetMembers(IEnumerable<Member> members)
		{
			if(members == null)
				return 0;

			return this.DataAccess.UpsertMany(members);
		}

		public int SetMembers(uint roleId, params Member[] members)
		{
			if(members == null || members.Length == 0)
				return 0;

			return this.SetMembers(roleId, members, false);
		}

		public int SetMembers(uint roleId, IEnumerable<Member> members, bool shouldResetting = false)
		{
			if(members == null)
				return 0;

			using(var transaction = new Zongsoft.Transactions.Transaction())
			{
				int count = 0;

				//清空指定角色的所有成员
				if(shouldResetting)
					count = this.DataAccess.Delete<Member>(Condition.Equal(nameof(Member.RoleId), roleId));

				//写入指定的角色成员集到数据库中
				count = this.DataAccess.UpsertMany<Member>(members.Select(m => new Member(roleId, m.MemberId, m.MemberType)));

				//提交事务
				transaction.Commit();

				return count;
			}
		}

		public bool RemoveMember(uint roleId, uint memberId, MemberType memberType)
		{
			return this.DataAccess.Delete<Member>(
				Condition.Equal(nameof(Member.RoleId), roleId) &
				Condition.Equal(nameof(Member.MemberId), memberId) &
				Condition.Equal(nameof(Member.MemberType), memberType)) > 0;
		}

		public int RemoveMembers(uint roleId)
		{
			return this.DataAccess.Delete<Member>(Condition.Equal(nameof(Member.RoleId), roleId));
		}
		#endregion
	}
}