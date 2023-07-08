using System.Net;
using Newtonsoft.Json;
using Microsoft.AspNetCore.WebUtilities;
using Newtonsoft.Json.Linq;
using Ganss.Xss;

namespace DotNetXssMiddleware.Middlewares
{
   

    public class AntiXssMiddleware
    {
        private readonly RequestDelegate _next;

        public AntiXssMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Check query string
            var queryString = context.Request.QueryString.Value;
            if (IsMaliciousQuery(queryString))
            {
                await RespondWithAnError(context).ConfigureAwait(false);
                return;
            }

            // Check URL path
            var urlPath = context.Request.Path.Value;
            if (IsMalicious(urlPath))
            {
                await RespondWithAnError(context).ConfigureAwait(false);
                return;
            }

            if (context.Request.HasFormContentType)
            {
                // Check form data
                var form = await context.Request.ReadFormAsync();
                foreach (var key in form.Keys)
                {
                    // Ignore fields with binary data, such as images
                    var file = form.Files.GetFile(key);
                    if (file == null || !file.ContentType.StartsWith("image/"))
                    {
                        if (IsMalicious(form[key]))
                        {
                            await RespondWithAnError(context).ConfigureAwait(false);
                            return;
                        }
                    }
                }
            }

            // Check body content
            if (context.Request.ContentType != null && context.Request.ContentType.Contains("application/json"))
            {
                var originalBodyStream = context.Request.Body;

                try
                {
                    using var newBodyStream = new MemoryStream();
                    await originalBodyStream.CopyToAsync(newBodyStream);

                    newBodyStream.Seek(0, SeekOrigin.Begin);
                    using var reader = new StreamReader(newBodyStream);
                    var requestBody = await reader.ReadToEndAsync();

                    if (IsMaliciousJson(requestBody))
                    {
                        await RespondWithAnError(context).ConfigureAwait(false);
                        return;
                    }

                    newBodyStream.Seek(0, SeekOrigin.Begin);
                    context.Request.Body = newBodyStream;

                    await _next(context);
                }
                finally
                {
                    context.Request.Body = originalBodyStream;
                }
            }
            else
            {
                await _next(context);
            }
        }

       
        private static bool IsMalicious(string input)
        {
            // Replace newlines with placeholders
           
            const string newlineRN = "{NEWLINE_RN}";
            const string newlineN = "{NEWLINE_N}";
            string replacedInput = input.Replace("\r\n", newlineRN)
                                        .Replace("\n", newlineN);

            // Sanitize the input
            var sanitizer = new HtmlSanitizer();
            string sanitizedInput = sanitizer.Sanitize(replacedInput);

            // Revert the newline placeholders
            sanitizedInput = sanitizedInput.Replace(newlineRN, "\r\n")
                                           .Replace(newlineN, "\n");

            return !sanitizedInput.Equals(input);
        }
        private static bool IsMaliciousQuery(string queryString)
        {
            var queryDictionary = QueryHelpers.ParseQuery(queryString);

            foreach (var keyValuePair in queryDictionary)
            {
                var key = keyValuePair.Key;
                var value = keyValuePair.Value.ToString();

                if (IsMalicious(key) || IsMalicious(value))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsMaliciousJson(string jsonString)
        {
            if (String.IsNullOrEmpty(jsonString))
            {
                return false;
            }
            try
            {
                var jToken = JToken.Parse(jsonString);

                return jToken.Type switch
                {
                    JTokenType.Object => IsMaliciousJsonObject((JObject)jToken),
                    JTokenType.Array => IsMaliciousJsonArray((JArray)jToken),
                    _ => false
                };
            }
            catch (JsonReaderException)
            {
                return true;
            }
        }

        private static bool IsMaliciousJsonObject(JObject jObject)
        {
            foreach (var property in jObject.Properties())
            {
                var key = property.Name;
                var value = property.Value;

                if (IsMalicious(key))
                {
                    return true;
                }

                if (value.Type == JTokenType.String && IsMalicious(value.ToString()))
                {
                    return true;
                }

                if (value.Type == JTokenType.Object && IsMaliciousJsonObject((JObject)value))
                {
                    return true;
                }

                if (value.Type == JTokenType.Array && IsMaliciousJsonArray((JArray)value))
                {
                    return true;
                }
            }

            return false;
        }


        private static bool IsMaliciousJsonArray(JArray jArray)
        {
            foreach (var item in jArray)
            {
                if (item.Type == JTokenType.String && IsMalicious(item.ToString()))
                {
                    return true;
                }

                if (item.Type == JTokenType.Object && IsMaliciousJsonObject((JObject)item))
                {
                    return true;
                }

                if (item.Type == JTokenType.Array && IsMaliciousJsonArray((JArray)item))
                {
                    return true;
                }
            }

            return false;
        }


        private async Task RespondWithAnError(HttpContext context)
        {
            context.Response.Clear();
            context.Response.ContentType = "application/json; charset=utf-8";
            context.Response.StatusCode = (int)HttpStatusCode.BadRequest;

            
                var _error = new ErrorResponse
                {
                    Message = "XSS Content detected",
                    Status = false,
                    ErrorCode = (int)HttpStatusCode.BadRequest
                };
            

            await context.Response.WriteAsync(JsonConvert.SerializeObject(_error));
        }


        
    }
    public class ErrorResponse
    {
        public int ErrorCode { get; set; }
        public bool Status { get; set; }
        public string Message { get; set; }
    }

}
