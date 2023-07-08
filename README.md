﻿﻿
# AntiXSS Middleware

The AntiXSS Middleware is a Asp .NET Core component designed to protect your application from cross-site scripting (XSS) attacks. It intercepts incoming HTTP requests and checks for potential malicious content in query strings, URL paths, form data, and JSON payloads.

## Installation

To use the AntiXSS Middleware in your Asp .NET Core application, follow these steps:

1. Install the required NuGet package:
   - Ganss.Xss

   You can install the package using the following command in the Package Manager Console:

   ```shell
   Install-Package HtmlSanitizer
 2. Copy the AntiXssMiddleware.cs file into your project.
 3. In your **`Program.cs`** file, add the middleware to the pipeline by invoking the 
    **`UseMiddleware`** method before the app.Run() method:
    
   
    ```csharp
      // call the middleware here
      app.UseMiddleware<AntiXssMiddleware>();

      app.Run();
     ```
## How It Works
The AntiXSS Middleware intercepts incoming HTTP requests and performs the following 

checks:

 * **Query String**: It examines the query string parameters for potential malicious content by 
     invoking the **`IsMaliciousQuery`** method.
     
 * **URL Path**: It checks the URL path for potential malicious content by invoking the 
     **`IsMalicious method`**.
     
 * **Form Data**: If the request has a form content type, it reads the form data and checks each 
   field for potential malicious content using the **`IsMalicious method`**. Fields with binary 
   data, such as images, are ignored.
   
 * **JSON Payload**: If the request content type is **`application/json`**, it reads the JSON 
   payload and checks for potential malicious content by invoking the **`IsMaliciousJson`**
   method. It handles both JSON objects and arrays recursively to scan all properties and values.
   
 If any potential malicious content is detected, the middleware responds with an error 
 message and a status code of **400 Bad Request**.
 
 
 
 ## Customization
 
 You can customize the behavior of the AntiXSS Middleware according to your requirements. 
 
 Here are a few possible modifications:
 
 * **Sanitization Rules**: The middleware uses the **`HtmlSanitizer`** class from the 
   **`Ganss.Xss`** package to sanitize input. You can adjust the sanitization rules or use ,
   a different sanitizer library based on your needs. 
   
 * **Error Response**: The **`RespondWithAnError`** method generates the error response when 
     malicious content is detected. You can modify the error message, status code, or format 
     the response in a different way.
     
  
  ## Contact

     For any questions or further discussion, feel free to reach out to me directly. 
     
     You can email me at goran.mustafa11@gmail.com
.
   
     
 

  
  

