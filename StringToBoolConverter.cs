using System.Text.Json.Serialization;
using System.Text.Json;
using System;
using System.Buffers;
using System.Buffers.Text;

namespace CyberArk.Extensions.Identity
{
    public class StringToBoolConverter : JsonConverter<bool>
    {
        public override bool Read(ref Utf8JsonReader reader, Type type, JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.String)
            {
              
                // try to parse bool directly from bytes
                ReadOnlySpan<byte> span = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
                if (Utf8Parser.TryParse(span, out bool flag, out int bytesConsumed) && span.Length == bytesConsumed)
                    return flag;

                // try to parse from a string if the above failed, this covers cases with other escaped/UTF characters
                if (Boolean.TryParse(reader.GetString(), out flag))
                    return flag;
            }

            // fallback to default handling
            return reader.GetBoolean();
        }

        public override void Write(Utf8JsonWriter writer, bool value, JsonSerializerOptions options)
        {
            writer.WriteBooleanValue(value);
        }
    }
}