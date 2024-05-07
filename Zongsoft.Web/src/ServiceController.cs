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
 * Copyright (C) 2010-2024 Zongsoft Studio <http://www.zongsoft.com>
 *
 * This file is part of Zongsoft.Web library.
 *
 * The Zongsoft.Web is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3.0 of the License,
 * or (at your option) any later version.
 *
 * The Zongsoft.Web is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the Zongsoft.Web library. If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;

using Zongsoft.Data;

namespace Zongsoft.Web
{
	public class ServiceController<TModel, TService> : ServiceControllerBase<TModel, TService> where TService : class, IDataService<TModel>
	{
		#region 公共方法
		[HttpGet("[area]/[controller]/{key:required}/[action]")]
		[HttpGet("[area]/[controller]/[action]/{key?}")]
		public virtual async Task<IActionResult> CountAsync(string key, CancellationToken cancellation = default)
		{
			return this.Content((await this.DataService.CountAsync(key, null, this.OptionsBuilder.Count(), cancellation)).ToString());
		}

		[HttpPost("[area]/[controller]/[action]")]
		public virtual async Task<IActionResult> CountAsync(CancellationToken cancellation = default)
		{
			if(this.DataService.Attribute == null || this.DataService.Attribute.Criteria == null)
				return this.StatusCode(StatusCodes.Status405MethodNotAllowed);

			var criteria = await Serialization.Serializer.Json.DeserializeAsync(this.Request.Body, this.DataService.Attribute.Criteria, cancellationToken: cancellation);
			var count = await this.DataService.CountAsync(Criteria.Transform(criteria as IModel), null, this.OptionsBuilder.Count(), cancellation);

			return this.Content(count.ToString());
		}

		[HttpGet("[area]/[controller]/{key:required}/[action]")]
		[HttpGet("[area]/[controller]/[action]/{key?}")]
		public virtual async Task<IActionResult> ExistsAsync(string key, CancellationToken cancellation = default)
		{
			return await this.DataService.ExistsAsync(key, this.OptionsBuilder.Exists(), cancellation) ? this.NoContent() : this.NotFound();
		}

		[HttpPost("[area]/[controller]/[action]")]
		public virtual async Task<IActionResult> ExistsAsync(CancellationToken cancellation = default)
		{
			if(this.DataService.Attribute == null || this.DataService.Attribute.Criteria == null)
				return this.StatusCode(StatusCodes.Status405MethodNotAllowed);

			var criteria = await Serialization.Serializer.Json.DeserializeAsync(this.Request.Body, this.DataService.Attribute.Criteria, cancellationToken: cancellation);
			var existed = await this.DataService.ExistsAsync(Criteria.Transform(criteria as IModel), this.OptionsBuilder.Exists(), cancellation);

			return existed ? this.NoContent() : this.NotFound();
		}

		[HttpGet("[area]/[controller]/{key?}")]
		public virtual async Task<IActionResult> GetAsync(string key, [FromQuery] Paging page = null, [FromQuery][ModelBinder(typeof(Binders.SortingBinder))] Sorting[] sort = null, CancellationToken cancellation = default)
		{
			page ??= Paging.Page(1);
			return this.Paginate(await this.OnGetAsync(key, page, sort, null, cancellation), page);
		}

		[HttpDelete("[area]/[controller]/{key?}")]
		public virtual async Task<IActionResult> DeleteAsync(string key, CancellationToken cancellation = default)
		{
			if(!this.CanDelete)
				return this.StatusCode(StatusCodes.Status405MethodNotAllowed);

			if(string.IsNullOrWhiteSpace(key))
			{
				var content = await this.Request.ReadAsStringAsync();

				if(string.IsNullOrWhiteSpace(content))
					return this.BadRequest();

				var parts = Common.StringExtension.Slice(content, ',', '|');

				if(parts != null && parts.Any())
				{
					var count = 0;

					using(var transaction = new Zongsoft.Transactions.Transaction())
					{
						foreach(var part in parts)
							count += await this.OnDeleteAsync(part, null, cancellation);

						transaction.Commit();
					}

					return count > 0 ? this.Content(count.ToString()) : this.NotFound();
				}
			}

			return await this.OnDeleteAsync(key, null, cancellation) > 0 ? this.NoContent() : this.NotFound();
		}

		[HttpPost("[area]/[controller]")]
		public virtual async Task<IActionResult> CreateAsync([FromBody] TModel model, CancellationToken cancellation = default)
		{
			if(!this.CanCreate)
				return this.StatusCode(StatusCodes.Status405MethodNotAllowed);

			//确认模型是否有效
			if(!this.TryValidateModel(model))
				return this.UnprocessableEntity();

			static object GetModelMemberValue(ref TModel target, string member)
			{
				if(target is IModel model)
					return model.TryGetValue(member, out var value) ? value : null;
				else
					return Reflection.Reflector.TryGetValue(ref target, member, out var value) ? value : null;
			}

			if(await this.OnCreateAsync(model, null, cancellation) > 0)
			{
				var keys = this.DataService.DataAccess.Metadata.Entities[this.DataService.Name].Key;

				if(keys == null || keys.Length == 0)
					return this.CreatedAtAction("Get", this.RouteData.Values, model);

				var text = new System.Text.StringBuilder(50);

				for(int i = 0; i < keys.Length; i++)
				{
					if(text.Length > 0)
						text.Append('-');

					text.Append(GetModelMemberValue(ref model, keys[0].Name)?.ToString());
				}

				this.RouteData.Values["key"] = text.ToString();
				return this.CreatedAtAction("Get", this.RouteData.Values, model);
			}

			return this.Conflict();
		}

		[HttpPut("[area]/[controller]")]
		public virtual async Task<IActionResult> UpsertAsync([FromBody] TModel model, CancellationToken cancellation = default)
		{
			if(!this.CanUpsert)
				return this.StatusCode(StatusCodes.Status405MethodNotAllowed);

			//确认模型是否有效
			if(!this.TryValidateModel(model))
				return this.UnprocessableEntity();

			return await this.OnUpsertAsync(model, null, cancellation) > 0 ? this.Ok(model) : this.Conflict();
		}

		[HttpPatch("[area]/[controller]/{key}")]
		public virtual async Task<IActionResult> UpdateAsync(string key, [FromBody] TModel model, CancellationToken cancellation = default)
		{
			if(!this.CanUpdate)
				return this.StatusCode(StatusCodes.Status405MethodNotAllowed);

			//确认模型是否有效
			if(!this.TryValidateModel(model))
				return this.UnprocessableEntity();

			return await this.OnUpdateAsync(key, model, null, cancellation) > 0 ? this.NoContent() : this.NotFound();
		}

		[HttpPost("[area]/[controller]/[action]")]
		public virtual async Task<IActionResult> QueryAsync([FromQuery] Paging page = null, [FromQuery][ModelBinder(typeof(Binders.SortingBinder))] Sorting[] sort = null, CancellationToken cancellation = default)
		{
			if(this.DataService.Attribute == null || this.DataService.Attribute.Criteria == null)
				return this.StatusCode(StatusCodes.Status405MethodNotAllowed);

			page ??= Paging.Page(1);
			var criteria = await Serialization.Serializer.Json.DeserializeAsync(this.Request.Body, this.DataService.Attribute.Criteria, cancellationToken: cancellation);
			var result = await this.DataService.SelectAsync(Criteria.Transform(criteria as IModel), this.GetSchema(), page, this.OptionsBuilder.Select(), sort, cancellation);

			return this.Paginate(result, page);
		}
		#endregion

		#region 虚拟方法
		protected virtual Task<object> OnGetAsync(string key, Paging page, Sorting[] sortings, IEnumerable<KeyValuePair<string, object>> parameters, CancellationToken cancellation = default)
		{
			return this.DataService.GetAsync(key, this.GetSchema(), page ?? Paging.Page(1), this.OptionsBuilder.Get(parameters), sortings, cancellation);
		}

		protected virtual Task<int> OnDeleteAsync(string key, IEnumerable<KeyValuePair<string, object>> parameters, CancellationToken cancellation = default)
		{
			return string.IsNullOrWhiteSpace(key) ? Task.FromResult(0) : this.DataService.DeleteAsync(key, this.GetSchema(), this.OptionsBuilder.Delete(parameters), cancellation);
		}

		protected virtual Task<int> OnCreateAsync(TModel model, IEnumerable<KeyValuePair<string, object>> parameters, CancellationToken cancellation = default)
		{
			return this.DataService.InsertAsync(model, this.GetSchema(), this.OptionsBuilder.Insert(parameters), cancellation);
		}

		protected virtual Task<int> OnUpdateAsync(string key, TModel model, IEnumerable<KeyValuePair<string, object>> parameters, CancellationToken cancellation = default)
		{
			return string.IsNullOrWhiteSpace(key) ?
				this.DataService.UpdateAsync(model, this.GetSchema(), this.OptionsBuilder.Update(parameters), cancellation) :
				this.DataService.UpdateAsync(key, model, this.GetSchema(), this.OptionsBuilder.Update(parameters), cancellation);
		}

		protected virtual Task<int> OnUpsertAsync(TModel model, IEnumerable<KeyValuePair<string, object>> parameters, CancellationToken cancellation = default)
		{
			return this.DataService.UpsertAsync(model, this.GetSchema(), this.OptionsBuilder.Upsert(parameters), cancellation);
		}
		#endregion
	}

	public class SubserviceController<TModel, TService> : ServiceControllerBase<TModel, TService> where TService : class, IDataService<TModel>
	{
		#region 公共方法
		[HttpGet("[area]/[controller]/{key:required}/[action]")]
		public virtual async Task<IActionResult> CountAsync(string key, CancellationToken cancellation = default)
		{
			if(string.IsNullOrWhiteSpace(key))
				return this.BadRequest();

			return this.Content((await this.DataService.CountAsync(key, null, this.OptionsBuilder.Count(), cancellation)).ToString());
		}

		[HttpPost("[area]/[controller]/[action]")]
		public virtual async Task<IActionResult> CountAsync(CancellationToken cancellation = default)
		{
			if(this.DataService.Attribute == null || this.DataService.Attribute.Criteria == null)
				return this.StatusCode(StatusCodes.Status405MethodNotAllowed);

			var criteria = await Serialization.Serializer.Json.DeserializeAsync(this.Request.Body, this.DataService.Attribute.Criteria, cancellationToken: cancellation);
			var count = await this.DataService.CountAsync(Criteria.Transform(criteria as IModel), null, this.OptionsBuilder.Count(), cancellation);
			return this.Content(count.ToString());
		}

		[HttpGet("[area]/[controller]/[action]/{key:required}")]
		public virtual async Task<IActionResult> ExistsAsync(string key, CancellationToken cancellation = default)
		{
			if(string.IsNullOrWhiteSpace(key))
				return this.BadRequest();

			return await this.DataService.ExistsAsync(key, this.OptionsBuilder.Exists(), cancellation) ? this.NoContent() : this.NotFound();
		}

		[HttpPost("[area]/[controller]/[action]")]
		public virtual async Task<IActionResult> ExistsAsync(CancellationToken cancellation = default)
		{
			if(this.DataService.Attribute == null || this.DataService.Attribute.Criteria == null)
				return this.StatusCode(StatusCodes.Status405MethodNotAllowed);

			var criteria = await Serialization.Serializer.Json.DeserializeAsync(this.Request.Body, this.DataService.Attribute.Criteria, cancellationToken: cancellation);
			var existed = await this.DataService.ExistsAsync(Criteria.Transform(criteria as IModel), this.OptionsBuilder.Exists(), cancellation);

			return existed ? this.NoContent() : this.NotFound();
		}

		[HttpGet("[area]/{key:required}/[controller]")]
		[HttpGet("[area]/[controller]/{key:required}")]
		public virtual async Task<IActionResult> GetAsync(string key, [FromQuery] Paging page = null, [FromQuery][ModelBinder(typeof(Binders.SortingBinder))] Sorting[] sort = null, CancellationToken cancellation = default)
		{
			if(string.IsNullOrWhiteSpace(key))
				return this.BadRequest();

			page ??= Paging.Page(1);
			return this.Paginate(await this.OnGetAsync(key, page, sort, null, cancellation), page);
		}

		[HttpDelete("[area]/{key:required}/[controller]")]
		[HttpDelete("[area]/[controller]/{key?}")]
		public virtual async Task<IActionResult> DeleteAsync(string key, CancellationToken cancellation = default)
		{
			if(!this.CanDelete)
				return this.StatusCode(StatusCodes.Status405MethodNotAllowed);

			if(string.IsNullOrWhiteSpace(key))
			{
				var content = await this.Request.ReadAsStringAsync();

				if(string.IsNullOrWhiteSpace(content))
					return this.BadRequest();

				var parts = Common.StringExtension.Slice(content, ',', '|');

				if(parts != null && parts.Any())
				{
					var count = 0;

					using(var transaction = new Zongsoft.Transactions.Transaction())
					{
						foreach(var part in parts)
							count += await this.OnDeleteAsync(part, null, cancellation);

						transaction.Commit();
					}

					return count > 0 ? this.Content(count.ToString()) : this.NotFound();
				}
			}

			return await this.OnDeleteAsync(key, null, cancellation) > 0 ? this.NoContent() : this.NotFound();
		}

		[HttpPost("[area]/{key:required}/[controller]")]
		public virtual async Task<IActionResult> CreateAsync(string key, [FromBody]IEnumerable<TModel> data, CancellationToken cancellation = default)
		{
			if(!this.CanCreate)
				return this.StatusCode(StatusCodes.Status405MethodNotAllowed);

			if(string.IsNullOrWhiteSpace(key))
				return this.BadRequest();

			//确认模型是否有效
			if(!this.TryValidateModel(data))
				return this.UnprocessableEntity();

			if(await this.OnCreateAsync(key, data, null, cancellation) > 0)
				return this.Created(this.Request.Path, data);

			return this.Conflict();
		}

		[HttpPut("[area]/{key:required}/[controller]")]
		public virtual async Task<IActionResult> UpsertAsync(string key, [FromBody]IEnumerable<TModel> data, CancellationToken cancellation = default)
		{
			if(!this.CanUpsert)
				return this.StatusCode(StatusCodes.Status405MethodNotAllowed);

			if(string.IsNullOrWhiteSpace(key))
				return this.BadRequest();

			//确认模型是否有效
			if(!this.TryValidateModel(data))
				return this.UnprocessableEntity();

			return await this.OnUpsertAsync(key, data, null, cancellation) > 0 ? this.Ok(data) : this.Conflict();
		}

		[HttpPatch("[area]/{key:required}/[controller]")]
		public virtual async Task<IActionResult> UpdateAsync(string key, [FromBody]IEnumerable<TModel> data, CancellationToken cancellation = default)
		{
			if(!this.CanUpdate)
				return this.StatusCode(StatusCodes.Status405MethodNotAllowed);

			if(string.IsNullOrWhiteSpace(key))
				return this.BadRequest();

			//确认模型是否有效
			if(!this.TryValidateModel(data))
				return this.UnprocessableEntity();

			return await this.OnUpdateAsync(key, data, null, cancellation) > 0 ? this.NoContent() : this.NotFound();
		}

		[HttpPost("[area]/[controller]/[action]")]
		public virtual async Task<IActionResult> QueryAsync([FromQuery]Paging page = null, [FromQuery][ModelBinder(typeof(Binders.SortingBinder))]Sorting[] sort = null, CancellationToken cancellation = default)
		{
			if(this.DataService.Attribute == null || this.DataService.Attribute.Criteria == null)
				return this.StatusCode(StatusCodes.Status405MethodNotAllowed);

			page ??= Paging.Page(1);
			var criteria = await Serialization.Serializer.Json.DeserializeAsync(this.Request.Body, this.DataService.Attribute.Criteria, cancellationToken: cancellation);
			var result = await this.DataService.SelectAsync(Criteria.Transform(criteria as IModel), this.GetSchema(), page, this.OptionsBuilder.Select(), sort, cancellation);

			return this.Paginate(result, page);
		}
		#endregion

		#region 虚拟方法
		protected virtual Task<object> OnGetAsync(string key, Paging page, Sorting[] sortings, IEnumerable<KeyValuePair<string, object>> parameters, CancellationToken cancellation = default)
		{
			return this.DataService.GetAsync(key, this.GetSchema(), page ?? Paging.Page(1), this.OptionsBuilder.Get(parameters), sortings, cancellation);
		}

		protected virtual Task<int> OnDeleteAsync(string key, IEnumerable<KeyValuePair<string, object>> parameters, CancellationToken cancellation = default)
		{
			return string.IsNullOrWhiteSpace(key) ? Task.FromResult(0) : this.DataService.DeleteAsync(key, this.GetSchema(), this.OptionsBuilder.Delete(parameters), cancellation);
		}

		protected virtual Task<int> OnCreateAsync(string key, IEnumerable<TModel> data, IEnumerable<KeyValuePair<string, object>> parameters, CancellationToken cancellation = default)
		{
			return this.DataService.InsertManyAsync(key, data, this.GetSchema(), this.OptionsBuilder.Insert(parameters), cancellation);
		}

		protected virtual Task<int> OnUpsertAsync(string key, IEnumerable<TModel> data, IEnumerable<KeyValuePair<string, object>> parameters, CancellationToken cancellation = default)
		{
			return this.DataService.UpsertManyAsync(key, data, this.GetSchema(), this.OptionsBuilder.Upsert(parameters), cancellation);
		}

		protected virtual Task<int> OnUpdateAsync(string key, IEnumerable<TModel> data, IEnumerable<KeyValuePair<string, object>> parameters, CancellationToken cancellation = default)
		{
			return this.DataService.UpdateManyAsync(key, data, this.GetSchema(), this.OptionsBuilder.Update(parameters), cancellation);
		}
		#endregion
	}
}