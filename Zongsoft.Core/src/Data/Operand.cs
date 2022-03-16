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

namespace Zongsoft.Data
{
	/// <summary>
	/// 表示操作元的基类。
	/// </summary>
	public abstract class Operand
	{
		#region 构造函数
		protected Operand(OperandType type)
		{
			this.Type = type;
		}
		#endregion

		#region 公共属性
		public OperandType Type { get; }
		#endregion

		#region 静态方法
		public static FieldOperand Field(string name) => new FieldOperand(name);
		public static ConstantOperand<T> Constant<T>(T value) => new ConstantOperand<T>(value);
		public static FunctionOperand Function(string name, params Operand[] arguments) => new FunctionOperand(name, arguments);
		public static AggregateOperand Aggregate(DataAggregateFunction aggregate, string member, bool distinct = false) => new AggregateOperand(aggregate, member, null, distinct);
		public static AggregateOperand Aggregate(DataAggregateFunction aggregate, string member, ICondition filter, bool distinct = false) => new AggregateOperand(aggregate, member, filter, distinct);

		public static string GetSymbol(OperandType type)
		{
			return type switch
			{
				OperandType.Add => "+",
				OperandType.Subtract => "-",
				OperandType.Multiply => "*",
				OperandType.Divide => "/",
				OperandType.Modulo => "%",
				OperandType.And => "&",
				OperandType.Or => "|",
				OperandType.Xor => "^",
				OperandType.Not => "!",
				OperandType.Negate => "-",
				_ => string.Empty,
			};
		}
		#endregion

		#region 符号重写
		public static Operand operator !(Operand operand) => new UnaryOperand(OperandType.Not, operand);
		public static Operand operator ~(Operand operand) => new UnaryOperand(OperandType.Not, operand);
		public static Operand operator -(Operand operand) => new UnaryOperand(OperandType.Negate, operand);

		public static Operand operator +(Operand a, Operand b) => new BinaryOperand(OperandType.Add, a, b);
		public static Operand operator -(Operand a, Operand b) => new BinaryOperand(OperandType.Subtract, a, b);
		public static Operand operator *(Operand a, Operand b) => new BinaryOperand(OperandType.Multiply, a, b);
		public static Operand operator /(Operand a, Operand b) => new BinaryOperand(OperandType.Divide, a, b);
		public static Operand operator %(Operand a, Operand b) => new BinaryOperand(OperandType.Modulo, a, b);
		public static Operand operator &(Operand a, Operand b) => new BinaryOperand(OperandType.And, a, b);
		public static Operand operator |(Operand a, Operand b) => new BinaryOperand(OperandType.Or, a, b);
		public static Operand operator ^(Operand a, Operand b) => new BinaryOperand(OperandType.Xor, a, b);
		#endregion

		#region 类型转化
		public static implicit operator Operand(byte value) => Constant(value);
		public static implicit operator Operand(sbyte value) => Constant(value);
		public static implicit operator Operand(short value) => Constant(value);
		public static implicit operator Operand(ushort value) => Constant(value);
		public static implicit operator Operand(int value) => Constant(value);
		public static implicit operator Operand(uint value) => Constant(value);
		public static implicit operator Operand(long value) => Constant(value);
		public static implicit operator Operand(ulong value) => Constant(value);
		public static implicit operator Operand(float value) => Constant(value);
		public static implicit operator Operand(double value) => Constant(value);
		public static implicit operator Operand(decimal value) => Constant(value);
		public static implicit operator Operand(bool value) => Constant(value);
		public static implicit operator Operand(char value) => Constant(value);
		public static implicit operator Operand(string value) => Constant(value);
		public static implicit operator Operand(DateTime value) => Constant(value);
		public static implicit operator Operand(DateTimeOffset value) => Constant(value);
		public static implicit operator Operand(Guid value) => Constant(value);
		#endregion

		#region 嵌套子类
		public class BinaryOperand : Operand, IEquatable<Operand>, IEquatable<BinaryOperand>
		{
			#region 构造函数
			public BinaryOperand(OperandType type, Operand left, Operand right) : base(type)
			{
				this.Left = left;
				this.Right = right;
			}
			#endregion

			#region 公共属性
			public Operand Left { get; }
			public Operand Right { get; }
			#endregion

			#region 重写方法
			public bool Equals(BinaryOperand other)
			{
				if(other is null)
					return false;

				return
					(
						(this.Left is null && other.Left is null) || (this.Left is not null && this.Left.Equals(other.Left))
					) &&
					(
						(this.Right is null && other.Right is null) || (this.Right is not null && this.Right.Equals(other.Right))
					);
			}

			public bool Equals(Operand other) => other is BinaryOperand binary && this.Equals(binary);
			public override bool Equals(object obj) => obj is BinaryOperand other && this.Equals(other);
			public override int GetHashCode() => HashCode.Combine(this.Left, this.Right);
			public override string ToString() => $"{this.Left} {GetSymbol(this.Type)} {this.Right}";
			#endregion
		}

		public class UnaryOperand : Operand, IEquatable<Operand>, IEquatable<UnaryOperand>
		{
			#region 构造函数
			public UnaryOperand(OperandType type, Operand operand) : base(type)
			{
				this.Operand = operand;
			}
			#endregion

			#region 公共属性
			public Operand Operand { get; }
			#endregion

			#region 重写方法
			public bool Equals(UnaryOperand other)
			{
				return other is not null && this.Type == other.Type &&
				(
					(this.Operand is null && other.Operand is null) ||
					(this.Operand is not null && this.Operand.Equals(other.Operand))
				);
			}

			public bool Equals(Operand other) => other is UnaryOperand unary && this.Equals(unary);
			public override bool Equals(object obj) => obj is UnaryOperand other && this.Equals(other);
			public override int GetHashCode() => HashCode.Combine(this.Type, this.Operand);
			public override string ToString() => $"{GetSymbol(this.Type)}{this.Operand}";
			#endregion
		}

		public class FunctionOperand : Operand, IEquatable<Operand>, IEquatable<FunctionOperand>
		{
			#region 构造函数
			public FunctionOperand(string name, params Operand[] arguments) : base(OperandType.Function)
			{
				if(string.IsNullOrWhiteSpace(name))
					throw new ArgumentNullException(nameof(name));

				this.Name = name.ToUpperInvariant();
				this.Arguments = arguments ?? Array.Empty<Operand>();
			}
			#endregion

			#region 公共属性
			public string Name { get; }
			public Operand[] Arguments { get; }
			#endregion

			#region 重写方法
			public bool Equals(FunctionOperand other)
			{
				if(other != null && string.Equals(this.Name, other.Name))
				{
					if((this.Arguments == null || this.Arguments.Length == 0) && (other.Arguments == null || other.Arguments.Length == 0))
						return true;

					if(this.Arguments.Length != other.Arguments.Length)
						return false;

					for(int i = 0; i < this.Arguments.Length; i++)
					{
						var a = this.Arguments[i];
						var b = other.Arguments[i];

						if(a is null)
						{
							if(b is null)
								continue;
							else
								return false;
						}
						else
						{
							if(b is null || a.GetType() != b.GetType())
								return false;
							if(!a.Equals(b))
								return false;
						}
					}

					return true;
				}

				return false;
			}

			public bool Equals(Operand operand) => operand is FunctionOperand other && this.Equals(other);
			public override bool Equals(object obj) => obj is FunctionOperand other && this.Equals(other);
			public override int GetHashCode()
			{
				if(this.Arguments == null || this.Arguments.Length == 0)
					return HashCode.Combine(this.Name);

				int code = 0;
				for(int i = 0; i < this.Arguments.Length; i++)
					code = HashCode.Combine(code, this.Arguments[i]);

				return HashCode.Combine(this.Name, code);
			}
			public override string ToString() => this.Arguments == null || this.Arguments.Length == 0 ? $"{this.Name}()" : $"{this.Name}(...)";
			#endregion
		}

		public class AggregateOperand : Operand, IEquatable<Operand>, IEquatable<AggregateOperand>
		{
			#region 构造函数
			public AggregateOperand(DataAggregateFunction function, string member, ICondition filter = null, bool distinct = false) : base(OperandType.Function)
			{
				if(string.IsNullOrWhiteSpace(member))
					throw new ArgumentNullException(nameof(member));

				this.Function = function;
				this.Member = member ?? string.Empty;
				this.Distinct = distinct;
				this.Filter = filter;
			}
			#endregion

			#region 公共属性
			public new DataAggregateFunction Function { get; }
			public string Member { get; }
			public bool Distinct { get; }
			public ICondition Filter { get; set; }
			#endregion

			#region 重写方法
			public bool Equals(AggregateOperand other)
			{
				return other != null &&
					this.Function == other.Function &&
					this.Distinct == other.Distinct &&
					(
						(string.IsNullOrEmpty(this.Member) && string.IsNullOrEmpty(other.Member)) ||
						string.Equals(this.Member, other.Member, StringComparison.OrdinalIgnoreCase)
					)&&
					(
						(this.Filter is null && other.Filter is null) ||
						(this.Filter is not null && this.Filter.Equals(other.Filter))
					);
			}

			public bool Equals(Operand operand) => operand is AggregateOperand aggregate && this.Equals(aggregate);
			public override bool Equals(object obj) => obj is AggregateOperand aggregate && this.Equals(aggregate);
			public override int GetHashCode() => HashCode.Combine(this.Function, this.Member, this.Distinct, this.Filter);
			public override string ToString() => $"{this.Function}({this.Member})";
			#endregion
		}

		public class FieldOperand : Operand, IEquatable<Operand>, IEquatable<FieldOperand>
		{
			#region 构造函数
			public FieldOperand(string name) : base(OperandType.Field)
			{
				if(string.IsNullOrWhiteSpace(name))
					throw new ArgumentNullException(nameof(name));

				this.Name = name.Trim();
			}
			#endregion

			#region 公共属性
			public string Name { get; }
			#endregion

			#region 重写方法
			public bool Equals(FieldOperand other) => other is not null && string.Equals(this.Name, other.Name, StringComparison.OrdinalIgnoreCase);
			public bool Equals(Operand other) => other is FieldOperand field && this.Equals(field);
			public override bool Equals(object obj) => obj is FieldOperand operand && this.Equals(operand);
			public override int GetHashCode() => this.Name.ToLowerInvariant().GetHashCode();
			public override string ToString() => this.Name;
			#endregion
		}

		public class ConstantOperand<T> : Operand, IConvertible, IEquatable<Operand>, IEquatable<ConstantOperand<T>>
		{
			#region 构造函数
			public ConstantOperand(T value) : base(OperandType.Constant)
			{
				this.Value = value;
			}
			#endregion

			#region 公共属性
			public T Value { get; }
			#endregion

			#region 重写方法
			public override bool Equals(object obj) => obj switch
			{
				T value => this.Equals(value),
				ConstantOperand<T> operand => this.Equals(operand),
				_ => false,
			};

			public bool Equals(T other) => object.Equals(other, this.Value);
			public bool Equals(Operand other) => other is ConstantOperand<T> constant && this.Equals(constant);
			public bool Equals(ConstantOperand<T> other) => other is not null && object.Equals(this.Value, other.Value);
			public override int GetHashCode() => HashCode.Combine(this.Value);
			public override string ToString() => this.Value == null ? "<NULL>" : this.Value.ToString();
			#endregion

			#region 符号重写
			public static implicit operator T(ConstantOperand<T> operand) => operand.Value;
			public static implicit operator ConstantOperand<T>(T value) => new ConstantOperand<T>(value);

			public static bool operator ==(ConstantOperand<T> a, ConstantOperand<T> b)
			{
				if(a is null || a.Value is null)
					return b is null || b.Value is null;
				else
					return b is not null && object.Equals(a.Value, b.Value);
			}

			public static bool operator !=(ConstantOperand<T> a, ConstantOperand<T> b) => !(a == b);
			#endregion

			#region 类型转换
			public char ToChar(IFormatProvider provider) => this.Value == null ? '\0' : (char)Convert.ChangeType(this.Value, TypeCode.Char, provider);
			public bool ToBoolean(IFormatProvider provider) => this.Value != null && (bool)Convert.ChangeType(this.Value, TypeCode.Boolean, provider);
			public byte ToByte(IFormatProvider provider) => this.Value == null ? (byte)0 : (byte)Convert.ChangeType(this.Value, TypeCode.Byte, provider);
			public sbyte ToSByte(IFormatProvider provider) => this.Value == null ? (sbyte)0 : (sbyte)Convert.ChangeType(this.Value, TypeCode.SByte, provider);
			public short ToInt16(IFormatProvider provider) => this.Value == null ? (short)0 : (short)Convert.ChangeType(this.Value, TypeCode.Int16, provider);
			public int ToInt32(IFormatProvider provider) => this.Value == null ? 0 : (int)Convert.ChangeType(this.Value, TypeCode.Int32, provider);
			public long ToInt64(IFormatProvider provider) => this.Value == null ? 0L : (long)Convert.ChangeType(this.Value, TypeCode.Int64, provider);
			public ushort ToUInt16(IFormatProvider provider) => this.Value == null ? (ushort)0 : (ushort)Convert.ChangeType(this.Value, TypeCode.UInt16, provider);
			public uint ToUInt32(IFormatProvider provider) => this.Value == null ? 0u : (uint)Convert.ChangeType(this.Value, TypeCode.UInt32, provider);
			public ulong ToUInt64(IFormatProvider provider) => this.Value == null ? 0 : (ulong)Convert.ChangeType(this.Value, TypeCode.UInt64, provider);
			public decimal ToDecimal(IFormatProvider provider) => this.Value == null ? 0m : (decimal)Convert.ChangeType(this.Value, TypeCode.Decimal, provider);
			public double ToDouble(IFormatProvider provider) => this.Value == null ? 0d : (double)Convert.ChangeType(this.Value, TypeCode.Double, provider);
			public float ToSingle(IFormatProvider provider) => this.Value == null ? 0f : (float)Convert.ChangeType(this.Value, TypeCode.Single, provider);
			public DateTime ToDateTime(IFormatProvider provider) => this.Value == null ? DateTime.MinValue : (DateTime)Convert.ChangeType(this.Value, TypeCode.DateTime, provider);
			public string ToString(IFormatProvider provider) => this.Value == null ? null : (string)Convert.ChangeType(this.Value, TypeCode.String, provider);
			public object ToObject() => this.Value;
			public TypeCode GetTypeCode() => this.Value == null ? TypeCode.Object : System.Type.GetTypeCode(this.Value.GetType());
			public object ToType(Type conversionType, IFormatProvider provider) => Convert.ChangeType(this.Value, conversionType, provider);
			#endregion
		}
		#endregion
	}
}
