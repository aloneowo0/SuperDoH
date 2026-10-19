//! Adapt JSON byte arrays to the byte-buffer visitors used by octseq/domain.
//! This preserves the upstream record model without reimplementing its codecs.
use serde::de::{
    self, DeserializeOwned, DeserializeSeed, EnumAccess, IntoDeserializer, VariantAccess, Visitor,
};
use serde::{Deserializer, forward_to_deserialize_any};
use serde_json::Value;

type Error = serde_json::Error;
pub fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, Error> {
    T::deserialize(Json(value))
}
struct Json(Value);
impl<'de> IntoDeserializer<'de, Error> for Json {
    type Deserializer = Self;
    fn into_deserializer(self) -> Self {
        self
    }
}
impl<'de> Deserializer<'de> for Json {
    type Error = Error;
    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Null => visitor.visit_unit(),
            Value::Bool(v) => visitor.visit_bool(v),
            Value::Number(v) => Value::Number(v).deserialize_any(visitor),
            Value::String(v) => visitor.visit_string(v),
            Value::Array(v) => {
                visitor.visit_seq(de::value::SeqDeserializer::new(v.into_iter().map(Json)))
            }
            Value::Object(v) => visitor.visit_map(de::value::MapDeserializer::new(
                v.into_iter().map(|(k, v)| (k, Json(v))),
            )),
        }
    }
    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        let bytes: Vec<u8> = serde_json::from_value(self.0)?;
        visitor.visit_byte_buf(bytes)
    }
    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_bytes(visitor)
    }
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if self.0.is_null() {
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        let value = if name == "Name" && self.0 == Value::String(String::new()) {
            Json(Value::String(".".into()))
        } else {
            self
        };
        visitor.visit_newtype_struct(value)
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self.0 {
            Value::String(key) => visitor.visit_enum(JsonEnum {
                key,
                value: Value::Null,
            }),
            Value::Object(map) if map.len() == 1 => {
                let (key, value) = map
                    .into_iter()
                    .next()
                    .ok_or_else(|| de::Error::custom("empty enum"))?;
                visitor.visit_enum(JsonEnum { key, value })
            }
            _ => Err(de::Error::custom("expected a single-variant record object")),
        }
    }
    forward_to_deserialize_any! {bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string unit unit_struct seq tuple tuple_struct map struct identifier ignored_any}
}
struct JsonEnum {
    key: String,
    value: Value,
}
impl<'de> EnumAccess<'de> for JsonEnum {
    type Error = Error;
    type Variant = Json;
    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, Json), Error> {
        let key = seed.deserialize(serde::de::value::StringDeserializer::<Error>::new(self.key))?;
        Ok((key, Json(self.value)))
    }
}
impl<'de> VariantAccess<'de> for Json {
    type Error = Error;
    fn unit_variant(self) -> Result<(), Error> {
        serde::Deserialize::deserialize(self)
    }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
        seed.deserialize(self)
    }
    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_any(visitor)
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_any(visitor)
    }
}
