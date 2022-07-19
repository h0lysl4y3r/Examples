using ContentConstants = Elia.EduCore.Service.Model.Content.Constants;
using Elia.EduCore.Common.Auth;
using Elia.EduCore.Common.Messaging;
using Elia.EduCore.Common.Web;
using Elia.EduCore.Service.Model.Content.Certificates;
using Elia.EduCore.Service.Model.Directory.Enums;
using ServiceStack.Html;
using System;
using System.Linq;
using System.Net;
using Elia.EduCore.Common;
using Elia.EduCore.Service.Model.Directory;

namespace Elia.EduCore.WebAPI.Services
{
	public partial class Service
	{
		#region Certificates

		[RequiresSession(typeof(GetCertificatesResponse))]
		public object Get(Model.Content.GetCertificates request)
		{
			var requestDto = new GetCertificates()
			{
			};

			return ForwardRequestToContentService<GetCertificates, GetCertificatesResponse>(requestDto, HttpVerbs.Get);
		}

		[RequiresSession(typeof(GetCertificateResponse))]
		public object Get(Model.Content.GetCertificate request)
		{
			var requestDto = new GetCertificate()
			{
				CertificateSlug = request.CertificateSlug
			};

			return ForwardRequestToContentService<GetCertificate, GetCertificateResponse>(requestDto, HttpVerbs.Get);
		}

		#endregion


		#region User Certificates

		[RequiresSession(typeof(GetUserCertificatesResponse))]
		public object Get(Model.Content.GetUserCertificates request)
		{
			var session = this.GetSession() as EduCoreUserSession;
			var userRoles = session.GetApplicationUserRoles(ApplicationSettings.Default.ApplicationSlug);
			var hasAppAdminRole = userRoles.Any(x => x.Role == RoleNames.AppAdministrator);
			var currentEduPersonId = session.EduPersonId.Value;

			// Only AppAdmin can request certificates of other users
			if (!hasAppAdminRole && request.EduPersonId > 0 && request.EduPersonId != currentEduPersonId)
				return Response.CreateInvalidParameter<GetUserCertificatesResponse>(nameof(GetUserCertificates.EduPersonId));

			// If no value is given, use current user
			if (request.EduPersonId == 0) request.EduPersonId = currentEduPersonId;

			var requestDto = new GetUserCertificates()
			{
				EduPersonId = request.EduPersonId
			};

			return ForwardRequestToContentService<GetUserCertificates, GetUserCertificatesResponse>(requestDto, HttpVerbs.Get);
		}

		[RequiresSession(typeof(GetUserCertificateResponse))]
		public object Get(Model.Content.GetUserCertificate request)
		{
			var requestDto = new GetUserCertificate()
			{
				Id = request.Id
			};

			var response = ForwardRequestToContentService<GetUserCertificate, GetUserCertificateResponse>(requestDto, HttpVerbs.Get);
			if (response != null && response.IsSuccess)
			{
				var session = this.GetSession() as EduCoreUserSession;
				var userRole = session.GetCurrentApplicationUserRole(ApplicationSettings.Default.ApplicationSlug);
				var userRoles = session.GetApplicationUserRoles(ApplicationSettings.Default.ApplicationSlug);
				var hasAppAdminRole = userRoles.Any(x => x.Role == RoleNames.AppAdministrator);
				var currentEduPersonId = session.EduPersonId.Value;
				var certificate = response.Data;

				// Only AppAdmin can request certificates of other users
				if (!hasAppAdminRole && certificate.EduPersonId != currentEduPersonId)
				{
					var isAllow = false;
					if (userRole.Role == RoleNames.Parent)
					{
						// Parent can request certificate of their own child
						var getParentChildrenRequest = new GetParentChildren()
						{
							ApplicationSlug = ApplicationSettings.Default.ApplicationSlug,
							RetreiveAvatarUrls = false
						};
						var getParentChildrenResponse = this.GetMessage<GetParentChildren, GetParentChildrenResponse>(getParentChildrenRequest, Configuration.GetServiceUrl(ServiceNames.DirectoryService));
						var responseBody = getParentChildrenResponse?.GetBody();

						if (responseBody == null || !responseBody.IsSuccess)
							return Response.CreateOrMerge<GetUserCertificateResponse>(responseBody);

						var childrenEduPersonIds = responseBody.Data.Select(x => x.EduPerson.Id);
						// Check whether requested id is subset of allowed ids
						isAllow = childrenEduPersonIds.Contains(certificate.EduPersonId);
					}

					if (!isAllow)
						return Response.Create<GetUserCertificateResponse>(HttpStatusCode.Forbidden, nameof(MessageTexts.ActionForbidden), MessageTexts.ActionForbidden);
				}
			}

			return response;
		}

		[RequiresRole(typeof(CreateUserCertificateResponse), RoleNames.AppAdministrator)]
		public object Post(Model.Content.CreateUserCertificate request)
		{
			if (request.EduPersonId <= 0) return Response.CreateInvalidParameter<CreateUserCertificateResponse>(nameof(CreateUserCertificate.EduPersonId));
			if (request.DateIssued == null) request.DateIssued = DateTimeOffset.UtcNow;
			if (string.IsNullOrWhiteSpace(request.CertificateSlug)) return Response.CreateInvalidParameter<CreateUserCertificateResponse>(nameof(CreateUserCertificate.CertificateSlug));

			var directoryHost = Configuration.GetServiceUrl(ServiceNames.DirectoryService);
			var getEduPersonByIdRequest = new GetEduPersonById()
			{
				Id = request.EduPersonId,
				RetreiveAppUserRoles = false,
				RetreiveAvatarUrl = false,
				ApplicationSlug = ApplicationSettings.Default.ApplicationSlug,
				RequestOrigin = Configuration.GetCurrentServiceUrl(),
			};
			var getEduPersonByIdResponse = ForwardRequest<GetEduPersonById, GetEduPersonByIdResponse>(getEduPersonByIdRequest, directoryHost, HttpVerbs.Get);
			if (!(getEduPersonByIdResponse?.IsSuccess ?? false))
				return Response.CreateOrMerge<CreateUserCertificateResponse>(getEduPersonByIdResponse);

			var metadata = new UserCertificateMetadataDto()
			{
				EduPersonId = request.EduPersonId,
				UserFirstName = getEduPersonByIdResponse.Data.FirstName,
				UserLastName = getEduPersonByIdResponse.Data.LastName,
				DateIssued = request.DateIssued.Value,
				Score = request.Score
			};

			var requestDto = new CreateUserCertificate()
			{
				EduPersonId = request.EduPersonId,
				CertificateSlug = request.CertificateSlug,
				AssignmentAssigneeResultId = request.AssignmentAssigneeResultId,
				Metadata = metadata
			};

			return ForwardRequestToContentService<CreateUserCertificate, CreateUserCertificateResponse>(requestDto, HttpVerbs.Post);
		}

		#endregion
	}
}
