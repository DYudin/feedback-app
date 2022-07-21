using Microsoft.Extensions.Configuration;
using Serilog;
using Business.Identity.Models;
using Business.Identity.IVerificationServiceProvider;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Business.Identity
{
    public class AuthPoint : IAuthPoint
    {
        private readonly IVerificationServiceProvider _verificationServiceProvider;
        private readonly ILogger _logger;
        private readonly IConfiguration _configuration;

        public AuthPoint(
            IVerificationServiceProvider verificationServiceProvider,
            ILogger logger,
            IConfiguration configuration)
        {
            _verificationServiceProvider = verificationServiceProvider;
            _logger = logger;
            _configuration = configuration;
        }

        public async Task<SendVerificationResult> SendVerificationAsync(VerificationInput input)
        {
            try
            {
                _logger.Info("Отправка верификации на телефон: " + input.Phone);
                var phone = input.Phone;
                var identityResult = SignInHelper.ValidatePhone(ref phone);
                if (!identityResult.Succeeded)
                {
                    return new SendVerificationResult() { isSuccess = false, message = identityResult.Errors.FirstOrDefault()?.Description };
                }

                var verificationService = _verificationServiceProvider.GetService(input.Type);

                string codeFromPhoneAuthRequest = isTestMode()
                    ? getDefaultCode()
                    : await verificationService.SendAsync(input);

                return new SendVerificationResult() { isSuccess = true, code = codeFromPhoneAuthRequest };
            }
            catch (Exception ex)
            {
                var fullMessage = $"Ошибка отправки верификации пользователя ({input.Phone}): {ex.Message}";
                _logger.Error(fullMessage, ex);

                var returnMsg = isTestMode()
                    ? fullMessage
                    : $"Ошибка отправки верификации пользователя {input.Phone}";
                return new SendVerificationResult() { isSuccess = false, message = returnMsg };
            }
        }

        public (bool isSuccess, string message) Verify(VerificationInput inputCodeData, SavedVerification savedCodeData)
        {
            string defaultCode = isTestMode()
                    ? getDefaultCode()
                    : null;

            var result = SignInHelper.VerifyCode(inputCodeData, savedCodeData, defaultCode);
            return (result.isSuccess, result.message);
        }

        private bool isTestMode()
        {
            return _configuration.GetValue<bool>("Services:Auth:PhoneAuthTestMode", true) &&
                (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development" ||
                Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Test");
        }

        private string getDefaultCode()
        {
            return _configuration.GetValue<string>("Services:Auth:DefaultAuthCode", null);
        }
    }
}
