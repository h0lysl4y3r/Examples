using System;
using System.Linq;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.Net;
using System.Security.Claims;
using System.Xml;
using Elia.EduCore.Common.DotNet;
using Elia.EduCore.Common.Helpers;
using Elia.EduCore.Service.Model;
using ServiceStack;
using ServiceStack.Auth;
using ServiceStack.Configuration;
using ServiceStack.Web;
using System.Web;
using Elia.EduCore.Service.Model.Directory;
using Elia.EduCore.Common.Messaging;
using System.Net.Mail;

namespace Elia.EduCore.Common.Auth
{
	/// <summary>
	/// Sustainsys SAML2 implementation of ADFS auth provider
	/// </summary>
	public class AdfsAuthProvider : AuthProvider, ISamlAuthProvider
	{
		public const string Name = "adfs";
		public const string Realm = "/auth/adfs";

		public const string FedAuthKey = "FedAuth";
		public const string FedAuthKey1 = "FedAuth1";

		public string LogoutUrlPath { get; set; }
		public string LogoutReplyUrl { get; set; }
		public Func<IServiceBase, IAuthSession, IAuthTokens, int, IHttpResult> AfterApplicationUserRolesFetchedFilter { get; set; }

		public AdfsAuthProvider(IAppSettings appSettings)
		{
			AuthRealm = Realm;
			Provider = Name;

			CallbackUrl = appSettings.GetString("adfs.CallbackUrl");
			if (CallbackUrl == null) throw new ArgumentNullException(nameof(CallbackUrl));
			RedirectUrl = appSettings.GetString("adfs.RedirectUrl");
			if (RedirectUrl == null) throw new ArgumentNullException(nameof(RedirectUrl));
			LogoutUrlPath = appSettings.GetString("adfs.LogoutUrlPath");
			if (LogoutUrlPath == null) throw new ArgumentNullException(nameof(LogoutUrlPath));
			LogoutReplyUrl = appSettings.GetString("adfs.LogoutReplyUrl");
			if (LogoutReplyUrl == null) throw new ArgumentNullException(nameof(LogoutReplyUrl));
		}

		protected IAuthTokens Init(IServiceBase authService, ref IAuthSession session, Authenticate request)
		{
			var tokens = session.ProviderOAuthAccess.FirstOrDefault(x => x.Provider == this.Provider);
			if (tokens == null)
			{
				session.ProviderOAuthAccess.Add(tokens = new AuthTokens { Provider = this.Provider });
			}
			return tokens;
		}

		public override IHttpResult OnAuthenticated(IServiceBase authService, IAuthSession session, IAuthTokens tokens, Dictionary<string, string> authInfo)
		{
			return base.OnAuthenticated(authService, session, tokens, authInfo)
				?? this.HandlePostAuthenticated(authService, session, tokens, authInfo, false,
					AfterApplicationUserRolesFetchedFilter ?? OnAfterApplicationUserRolesFetchedFilter);
		}

		public override object Authenticate(IServiceBase authService, IAuthSession session, Authenticate request)
		{
			var tokens = this.Init(authService, ref session, request);

			var referrerUrl = session.ReferrerUrl = GetReferrerUrl(authService, session, request);

			if (!HttpContext.Current.User.Identity.IsAuthenticated)
			{
				var loginUrl = CreateLoginUrl(authService, session, request);
				return new HttpResult
				{
					StatusCode = HttpStatusCode.SeeOther,
					Location = loginUrl.AbsoluteUri
				};
			}

			var authInfo = CreateAuthInfo(ClaimsPrincipal.Current.Claims.ToArray());
			if (authInfo == null)
			{
				var redirectUri = GetLogoutUri(HttpUtility.UrlEncode(referrerUrl.SetParam("f", "ActionForbidden")));
				return authService.Redirect(redirectUri.AbsoluteUri);
			}

			session.IsAuthenticated = true;

			var authenticated = OnAuthenticated(authService, session, tokens, authInfo as Dictionary<string, string>);
			if (authenticated != null) return authenticated;
			return authService.Redirect(SuccessRedirectUrlFilter(this, referrerUrl.SetParam("s", "1")));
		}

		protected virtual Uri CreateLoginUrl(IServiceBase authService, IAuthSession session, Authenticate request)
		{
			return null;
		}

		protected virtual IDictionary<string, string> CreateAuthInfo(Claim[] claims)
		{
			var authInfo = new Dictionary<string, string>();
			var roleCount = 0;
			foreach (var claim in claims)
			{
				var claimType = ConvertClaimTypeToAuthTokenType(claim.Type);
				if (claimType == null) continue;

				if (claimType == "role")
				{
					authInfo[claimType + (roleCount++ + 1)] = claim.Value;
					continue;
				}

				authInfo[claimType] = claim.Value;
			}

			if (!ValidateAuthInfo(authInfo)) return null;

			return authInfo;
		}

		protected virtual bool ValidateAuthInfo(Dictionary<string, string> authInfo)
		{
			if (authInfo == null) throw new ArgumentNullException(nameof(authInfo));

			if (!authInfo.ContainsKey("nameidentifier")
				&& !authInfo.ContainsKey("emailaddress")
				&& !authInfo.ContainsKey("upn"))
				return false;

			return true;
		}

		public override bool IsAuthorized(IAuthSession session, IAuthTokens tokens, Authenticate request = null)
		{
			if (request != null)
			{
				if (!LoginMatchesSession(session, request.UserName))
				{
					return false;
				}
			}

			var retVal = session != null && session.IsAuthenticated && tokens != null && !string.IsNullOrEmpty(tokens.UserId);
			return retVal;
		}

		protected override void LoadUserAuthInfo(AuthUserSession userSession, IAuthTokens tokens, Dictionary<string, string> authInfo)
		{
			// move authInfo data into tokens, try to keep naming conventions used by oath providers
			try
			{
				tokens.UserId = authInfo["nameidentifier"];
				tokens.FirstName = authInfo["givenname"];
				tokens.LastName = authInfo["surname"];
				tokens.DisplayName = authInfo["name"];
				tokens.Email = authInfo["emailaddress"];

				this.LoadUserOAuthProvider(userSession, tokens, authInfo.GetValueOrDefault("secondary_id"));
			}
			catch (Exception ex)
			{

				var service = HostContext.AppHost.Resolve<EduCoreService>();
				var applicationSlug = (HostContext.AppHost as IAwareOfApplication).ApplicationSlug;
				var serviceName = (HostContext.AppHost as AppHostBase).ServiceName;
				var requestOrigin = Configuration.GetCurrentServiceUrl();
				service.SendExceptionLog(serviceName, ex, requestOrigin, applicationSlug);
			}
		}

		protected void LoadUserOAuthProvider(IAuthSession authSession, IAuthTokens tokens, string userAuthId)
		{
			var userSession = authSession as AuthUserSession;
			if (userSession == null) return;

			userSession.UserAuthId = userSession.UserAuthId ?? userAuthId;
			userSession.UserName = userSession.UserName ?? tokens.UserName;
			userSession.DisplayName = userSession.DisplayName ?? tokens.DisplayName;
			userSession.FirstName = userSession.FirstName ?? tokens.FirstName;
			userSession.LastName = userSession.LastName ?? tokens.LastName;
			userSession.PrimaryEmail = userSession.PrimaryEmail ?? userSession.Email ?? tokens.Email;
			userSession.Email = userSession.Email ?? userSession.PrimaryEmail ?? tokens.Email;
		}

		protected virtual string ConvertClaimTypeToAuthTokenType(string claimType)
		{
			if (claimType == null) return null;

			switch (claimType)
			{
				case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn":
					return "upn";
				case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier":
					return "nameidentifier";
				case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":
					return "name";
				case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname":
					return "givenname";
				case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname":
					return "surname";
				case "http://schemas.microsoft.com/ws/2008/06/identity/claims/role":
					return "role";
				case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":
					return "emailaddress";
				default:
					return null;
			}
		}

		protected override string GetReferrerUrl(IServiceBase authService, IAuthSession session, Authenticate request = null)
		{
			if (request == null)
				request = authService.Request.Dto as Authenticate;

			// verify Continue URL authority
			var continueUrl = request?.Continue.GetUriSafe();
			if (continueUrl != null)
			{
				var allowedAuthorities = new List<string>()
				{
					new Uri(CallbackUrl).Authority,
					new Uri(RedirectUrl).Authority,
				};
				if (!allowedAuthorities.Contains(continueUrl.Authority)) continueUrl = null;
			}

			return
				continueUrl?.AbsoluteUri
				?? session.ReferrerUrl
				?? RedirectUrl;
		}

		public virtual Uri GetLogoutUri(string returnUrl)
		{
			returnUrl = returnUrl ?? HttpUtility.UrlEncode(LogoutUrlPath);
			var serviceUrl = Configuration.GetCurrentServiceUrl();
			return new Uri($"{serviceUrl}/Saml2/Logout?ReturnUrl={returnUrl}");
		}

		protected virtual IHttpResult OnAfterApplicationUserRolesFetchedFilter(IServiceBase authService, IAuthSession session, IAuthTokens tokens, int eduPersonId)
		{
			var service = authService as ServiceStack.Service;
			var applicationSlug = (HostContext.AppHost as IAwareOfApplication).ApplicationSlug;
			var serviceName = (HostContext.AppHost as AppHostBase).ServiceName;
			var typeName = typeof(UpdateEduPerson).Name;
			var requestOrigin = Configuration.GetCurrentServiceUrl();

			var rolesInInstitutions = ConvertItemsToRolesInInstitutions(tokens, session);
			var directoryRequestHost = Configuration.GetServiceUrl(ServiceNames.DirectoryService);

			// update person with new roles/relations
			var updateEduPersonRequest = new UpdateEduPerson()
			{
				Id = eduPersonId,
				RolesInInstitutions = rolesInInstitutions,
				ApplicationSlug = applicationSlug,
				RequestOrigin = requestOrigin,
			};
			var updateEduPersonResponse = service.PutMessage<UpdateEduPerson, UpdateEduPersonResponse>(updateEduPersonRequest,
				directoryRequestHost, session.Id)?
				.GetBody();

			// error
			if (!(updateEduPersonResponse?.IsSuccess ?? false))
			{
				service.SendServiceApiRequestLog(serviceName, typeName, updateEduPersonResponse, requestOrigin, session.UserAuthId, applicationSlug, nameof(AdfsAuthProvider));
				return service.RedirectError(updateEduPersonResponse, session);
			}

			return null;
		}

		protected RoleInInstitution[] ConvertItemsToRolesInInstitutions(IAuthTokens authTokens, IAuthSession session)
		{
			if (authTokens?.Items == null) return new RoleInInstitution[0];

			var roleInInstitutions = new List<RoleInInstitution>();
			foreach (var item in authTokens.Items)
			{
				if (item.Key.Contains("role"))
				{
					var roleInInstitution = ConvertValueToRoleInInstitution(item.Value, authTokens, session);
					if (roleInInstitution == null) continue;
					roleInInstitutions.Add(roleInInstitution);
				}
			}

			return roleInInstitutions.ToArray();
		}

		protected virtual RoleInInstitution ConvertValueToRoleInInstitution(string roleInstitutionValue, IAuthTokens authTokens, IAuthSession session)
		{
			return null;
		}

		public string GetRoleInInstitutionByPriority(AuthTokens authTokens)
		{
			var rolesInInstitutions = ConvertItemsToRolesInInstitutions(authTokens, null);
			if (rolesInInstitutions?.FirstOrDefault(x => x.DirectoryRole == RoleNames.AppAdministrator) != null)
				return RoleNames.AppAdministrator;
			if (rolesInInstitutions?.FirstOrDefault(x => x.DirectoryRole == RoleNames.SchoolAdministrator) != null)
				return RoleNames.SchoolAdministrator;
			if (rolesInInstitutions?.FirstOrDefault(x => x.DirectoryRole == RoleNames.Director) != null)
				return RoleNames.Director;
			if (rolesInInstitutions?.FirstOrDefault(x => x.DirectoryRole == RoleNames.Teacher) != null)
				return RoleNames.Teacher;
			if (rolesInInstitutions?.FirstOrDefault(x => x.DirectoryRole == RoleNames.Student) != null)
				return RoleNames.Student;
			if (rolesInInstitutions?.FirstOrDefault(x => x.DirectoryRole == RoleNames.Parent) != null)
				return RoleNames.Parent;
			return null;
		}
	}
}
