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
using System.Reflection;

using Microsoft.Extensions.Options;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Zongsoft.Services
{
	public static class ServiceCollectionExtension
	{
		#region 私有变量
		private static readonly MethodInfo ConfigureMethod = typeof(OptionsConfigurationExtension)
			.GetMethod("Configure", 1,
				BindingFlags.Public | BindingFlags.Static,
				null,
				new[] { typeof(IServiceCollection), typeof(string), typeof(IConfiguration) },
				null);
		#endregion

		public static void Register(this IServiceCollection services, Assembly assembly, IConfiguration configuration)
		{
			if(assembly == null)
				throw new ArgumentNullException(nameof(assembly));

			foreach(var exportedType in assembly.ExportedTypes)
			{
				var type = exportedType.GetTypeInfo();

				//如果是非公共类（含抽象类）则忽略
				if(type.IsNotPublic || !type.IsClass || (type.IsAbstract && !type.IsSealed))
					continue;

				var attribute = type.GetCustomAttribute<ServiceAttribute>(true);

				if(attribute != null)
					RegisterServices(services, type, attribute);

				if(configuration != null)
					RegisterOptions(services, type, configuration);
			}
		}

		private static void RegisterOptions(IServiceCollection services, TypeInfo type, IConfiguration configuration)
		{
			static Type GetOptionType(Type type)
			{
				return type.IsGenericType && type.GetGenericTypeDefinition() == typeof(IOptions<>) ?
				       type.GenericTypeArguments[0] : type;
			}

			var properties = type.DeclaredProperties.Where(p => p.IsDefined(typeof(Configuration.Options.OptionsAttribute), true));

			foreach(var property in properties)
			{
				var attribute = property.GetCustomAttribute<Configuration.Options.OptionsAttribute>(true);

				if(attribute != null)
				{
					var method = ConfigureMethod.MakeGenericMethod(GetOptionType(property.PropertyType));
					method.Invoke(null, new object[] { services, attribute.Name, configuration.GetSection(attribute.Path) });
				}
			}

			var fields = type.DeclaredFields.Where(p => p.IsDefined(typeof(Configuration.Options.OptionsAttribute), true));

			foreach(var field in fields)
			{
				var attribute = field.GetCustomAttribute<Configuration.Options.OptionsAttribute>(true);

				if(attribute != null)
				{
					var method = ConfigureMethod.MakeGenericMethod(GetOptionType(field.FieldType));
					method.Invoke(null, new object[] { services, attribute.Name, configuration.GetSection(attribute.Path) });
				}
			}
		}

		private static void RegisterServices(IServiceCollection services, TypeInfo type, ServiceAttribute attribute)
		{
			if(type.IsAbstract)
			{
				if(type.IsSealed)
					RegisterStaticMember(services, type, attribute.Provider, attribute.Members);

				return;
			}

			services.AddSingleton((Type)type);

			if(attribute.Contracts != null)
			{
				var contracts = attribute.Contracts;

				if(string.IsNullOrEmpty(attribute.Provider))
				{
					for(var i = 0; i < contracts.Length; i++)
					{
						services.AddSingleton(contracts[i], services => services.GetService(type));
					}
				}
				else
				{
					for(var i = 0; i < contracts.Length; i++)
					{
						var contract = ServiceModular.GenerateContract(attribute.Provider, contracts[i]);
						services.AddSingleton(contract, svcs => svcs.GetService(type));
					}
				}
			}
		}

		private static void RegisterStaticMember(IServiceCollection services, TypeInfo type, string module, string members)
		{
			if(string.IsNullOrEmpty(members))
				return;

			if(string.IsNullOrEmpty(module))
			{
				foreach(var member in Zongsoft.Common.StringExtension.Slice(members, ','))
				{
					var property = type.GetDeclaredProperty(member);

					if(property != null)
					{
						services.AddSingleton(property.PropertyType, property.GetValue(null));
						continue;
					}

					var field = type.GetDeclaredField(member);

					if(field != null)
					{
						services.AddSingleton(field.FieldType, field.GetValue(null));
						continue;
					}
				}
			}
			else
			{
				foreach(var member in Zongsoft.Common.StringExtension.Slice(members, ','))
				{
					var property = type.GetDeclaredProperty(member);

					if(property != null)
					{
						services.AddSingleton(ServiceModular.GenerateContract(module, property.PropertyType), property.GetValue(null));
						continue;
					}

					var field = type.GetDeclaredField(member);

					if(field != null)
					{
						services.AddSingleton(ServiceModular.GenerateContract(module, field.FieldType), field.GetValue(null));
						continue;
					}
				}
			}
		}
	}
}
