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
using System.Linq;
using System.Collections.Generic;

using Microsoft.Extensions.DependencyInjection;

namespace Zongsoft.Services
{
	public class ServiceProvider : IServiceProvider, IDisposable
	{
		#region 成员字段
		private readonly ServiceProviderOptions _options;
		private readonly IList<IServiceProvider> _providers;
		private readonly IServiceCollection _descriptors;
		private ServiceScopeFactoryProxy _scopeFactory;
		#endregion

		#region 构造函数
		public ServiceProvider(IServiceCollection descriptors, ServiceProviderOptions options = null)
		{
			_options = options;
			_providers = new List<IServiceProvider>();
			_descriptors = descriptors ?? new ServiceCollection();
		}

		public ServiceProvider(IServiceProvider provider, ServiceProviderOptions options = null)
		{
			_options = options;
			_providers = new List<IServiceProvider>() { provider ?? throw new ArgumentNullException(nameof(provider)) };
			_descriptors = new ServiceCollection();
		}
		#endregion

		#region 公共属性
		public IServiceCollection Descriptors
		{
			get => _descriptors;
		}
		#endregion

		#region 公共方法
		public object GetService(Type serviceType)
		{
			if(_descriptors.Count > 0)
			{
				_providers.Add(
					_options == null ?
					_descriptors.BuildServiceProvider() :
					_descriptors.BuildServiceProvider(_options));

				_scopeFactory = null;
				_descriptors.Clear();
			}

			if(serviceType == typeof(IServiceScopeFactory) && _providers.Count > 1)
			{
				if(_scopeFactory == null)
				{
					lock(this)
					{
						if(_scopeFactory == null)
							_scopeFactory = new ServiceScopeFactoryProxy(_providers.Select(p => p.GetRequiredService<IServiceScopeFactory>()));
					}
				}

				return _scopeFactory;
			}

			for(int i = _providers.Count - 1; i >= 0; i--)
			{
				var service = _providers[i].GetService(serviceType);

				if(service != null)
					return service;
			}

			return null;
		}

		public void Register(Type type, params Type[] contracts)
		{
			if(type == null)
				throw new ArgumentNullException(nameof(type));

			_descriptors.AddSingleton(type);

			if(contracts != null)
			{
				for(var i = 0; i < contracts.Length; i++)
				{
					_descriptors.AddSingleton(contracts[i], services => services.GetRequiredService(type));
				}
			}
		}
		#endregion

		#region 处置方法
		public void Dispose()
		{
			while(_providers.Count > 0)
			{
				if(_providers[0] is IDisposable disposable)
				{
					disposable.Dispose();
					_providers.Remove((IServiceProvider)disposable);
				}
			}
		}
		#endregion

		private class ServiceScopeFactoryProxy : IServiceScopeFactory
		{
			private readonly IEnumerable<IServiceScopeFactory> _factories;

			public ServiceScopeFactoryProxy(IEnumerable<IServiceScopeFactory> factories)
			{
				_factories = factories;
			}

			public IServiceScope CreateScope()
			{
				return new ServiceScopeProxy(_factories.Select(p => p.CreateScope()));
			}
		}

		private class ServiceScopeProxy : IServiceScope
		{
			private readonly IEnumerable<IServiceScope> _scopes;

			public ServiceScopeProxy(IEnumerable<IServiceScope> scopes)
			{
				_scopes = scopes;
			}

			public IServiceProvider ServiceProvider => new ServiceProviderProxy(_scopes.Select(p => p.ServiceProvider));

			public void Dispose()
			{
				foreach(var scope in _scopes)
					scope.Dispose();
			}
		}

		private class ServiceProviderProxy : IServiceProvider, IDisposable
		{
			private readonly IEnumerable<IServiceProvider> _providers;

			public ServiceProviderProxy(IEnumerable<IServiceProvider> providers)
			{
				_providers = providers;
			}

			public object GetService(Type serviceType)
			{
				foreach(var provider in _providers)
				{
					var instance = provider.GetService(serviceType);

					if(instance != null)
						return instance;
				}

				return null;
			}

			public void Dispose()
			{
				foreach(var provider in _providers)
				{
					if(provider is IDisposable disposable)
						disposable.Dispose();
				}
			}
		}
	}
}
