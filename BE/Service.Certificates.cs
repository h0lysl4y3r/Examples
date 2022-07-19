using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Web.Hosting;
using Elia.EduCore.Common;
using Elia.EduCore.Common.Auth;
using Elia.EduCore.Common.Helpers;
using Elia.EduCore.Common.Messaging;
using Elia.EduCore.Common.Web;
using Elia.EduCore.Service.Model.Content.Certificates;
using Elia.EduCore.Service.Model.FileProcessing;
using ServiceStack;

namespace Elia.EduCore.Service.FileProcessing.Services
{
	public partial class Service : EduCoreService
	{
		private static string CertificatePath = "~/Data/Certificates";
		private static string CertificateOutputRelativePath = "output/certificates";
		private static string CertificateOutputPath = "~/" + CertificateOutputRelativePath;
		private static ConcurrentDictionary<string, CertificateDto> CertificateMetadata = new ConcurrentDictionary<string, CertificateDto>();
		private static ConcurrentDictionary<string, DateTimeOffset> CertificateProcessing = new ConcurrentDictionary<string, DateTimeOffset>();

		[AuthorityRestricted()]
		public object Get(GetCertificateByMetadataHash request)
		{
			// validate
			var format = ValidateFormat(request.Format);
			if (format == null)
				throw new HttpError(HttpStatusCode.BadRequest, MessageTexts.InvalidExportFormat);
			//
			if (request.MetadataHash.IsNullOrEmpty())
				throw new HttpError(HttpStatusCode.BadRequest, MessageTexts.BadData);

			// first try find in output templates
			var baseFilePath = CreateOutputCertificateBaseFilePath(request.MetadataHash, request.Format);
			if (File.Exists(baseFilePath))
			{
				try
				{
					var bytes = File.ReadAllBytes(baseFilePath);
					return new FileStreamResult(bytes, Path.GetFileName(baseFilePath));
				}
				catch
				{
					throw new HttpError(HttpStatusCode.NotFound, MessageTexts.CertificateNotFound);
				}
			}

			var outputFilePath = CreateOutputCertificateFilePath(request.MetadataHash, request.Format);
			if (!File.Exists(outputFilePath))
				throw new HttpError(HttpStatusCode.NotFound, MessageTexts.ResourceNotFound);

			try
			{
				var bytes = File.ReadAllBytes(outputFilePath);
				return new FileStreamResult(bytes, Path.GetFileName(outputFilePath));
			}
			catch
			{
				throw new HttpError(HttpStatusCode.NotFound, MessageTexts.CertificateNotFound);
			}
		}

		[AuthorityRestricted(typeof(CreateCertificateResponse))]
		[RequiresSession(typeof(CreateCertificateResponse))]
		public object Post(CreateCertificate request)
		{
			// validate
			var format = ValidateFormat(request.Format);
			if (format == null)
				return Response.Create<CreateCertificateResponse>(HttpStatusCode.BadRequest,
					nameof(MessageTexts.InvalidExportFormat), MessageTexts.InvalidExportFormat);

			// get user cert from content
			var userCertficate = request.UserCertificateId > 0
				? GetUserCertificate(request.UserCertificateId, request.ApplicationSlug, request.SessionId)
				: null;

			// authorize
			if (userCertficate != null)
			{
				var session = GetSession() as EduCoreUserSession;
				var currentRole = session.GetCurrentApplicationUserRole(request.ApplicationSlug);
				if (session.EduPersonId != userCertficate.EduPersonId
					&& currentRole?.Role != RoleNames.AppAdministrator)
					return Response.Create<CreateCertificateResponse>(HttpStatusCode.Forbidden,
						nameof(MessageTexts.UserIsNotAuthorized), MessageTexts.UserIsNotAuthorized);
			}

			// validate
			if (userCertficate == null && request.CertificateSlug == null)
				return Response.Create<CreateCertificateResponse>(HttpStatusCode.NotFound,
					nameof(MessageTexts.UserCertificateNotFound), MessageTexts.UserCertificateNotFound);

			var certificateSlug = userCertficate?.CertificateSlug ?? request.CertificateSlug;

			// fetch template metadata
			CertificateDto certficate = null;
			if (!CertificateMetadata.TryGetValue(certificateSlug, out certficate))
			{
				// not found, fetch from content
				certficate = GetCertificate(certificateSlug, request.ApplicationSlug);
				if (certficate == null)
					return Response.Create<CreateCertificateResponse>(HttpStatusCode.NotFound,
						nameof(MessageTexts.CertificateNotFound), MessageTexts.CertificateNotFound);

				CertificateMetadata[certificateSlug] = certficate;
			}

			var metadataHash = userCertficate?.MetadataHash ?? certificateSlug;

			// create output path
			var outputFilePath = CreateOutputCertificateFilePath(metadataHash, format, certificateSlug);
			if (File.Exists(outputFilePath))
			{
				CertificateProcessing.TryRemove(metadataHash, out _);
				return new CreateCertificateResponse()
				{
					Data = new CreateCertificateState()
					{
						Done = true,
						MetadataHash = metadataHash
					}
				};
			}

			// in progress?
			DateTimeOffset lastProcessing;
			var utcNow = DateTimeOffset.UtcNow;
			if (CertificateProcessing.TryGetValue(metadataHash, out lastProcessing))
			{
				// in progress within 90s time window?
				if ((utcNow - lastProcessing).TotalSeconds < 90)
				{
					return new CreateCertificateResponse()
					{
						Data = new CreateCertificateState()
						{
							MetadataHash = metadataHash
						}
					};
				}
			}
			CertificateProcessing[metadataHash] = DateTimeOffset.UtcNow;

			// substitute html
			var certificateHtml = SubstituteCertificateHtml(certificateSlug, request.Language, userCertficate?.Metadata, userCertficate?.MetadataHash);
			if (certificateHtml == null)
				return Response.Create<CreateCertificateResponse>(HttpStatusCode.BadRequest,
					nameof(MessageTexts.InvalidLanguage), MessageTexts.InvalidLanguage);


			// create certficate file on the background
			HostingEnvironment.QueueBackgroundWorkItem(ct =>
			{
				// create PDF
				var pdfFilePath = CreateOutputCertificateFilePath(metadataHash, "pdf", certificateSlug);
				if (!File.Exists(outputFilePath)) {

					var htmlFolder = (CertificatePath + "/" + certificateSlug + "/html").MapServerPath();

					var renderer = new IronPdf.HtmlToPdf
					{
						PrintOptions =
						{
							CssMediaType = IronPdf.Rendering.PdfCssMediaType.Print,
							MarginLeft = 0,
							MarginRight = 0,
							MarginTop = 0,
							MarginBottom = 0,
							FitToPaperWidth = false,
							Zoom = 100
						}
					};
					renderer.PrintOptions.SetCustomPaperSizeinMilimeters(certficate.PaperWidth, certficate.PaperHeight);

					var pdfOutputDirectory = Path.GetDirectoryName(pdfFilePath);
					IOHelpers.EnsureDirectory(pdfOutputDirectory);

					var creator = renderer.RenderHtmlAsPdf(certificateHtml, htmlFolder);
					creator.SaveAs(pdfFilePath);
				}

				var outputDirectory = Path.GetDirectoryName(outputFilePath);
				IOHelpers.EnsureDirectory(outputDirectory);

				// the built-in resolution clamping is not working - so use a calculated DPI instead
				var maxDPI = MaxDPIForResolution(certficate.PaperWidth, certficate.PaperHeight, 2048, 2048);
				var dpi = Math.Min(maxDPI, 600);

				if (format == "png") {
					var pdf = IronPdf.PdfDocument.FromFile(pdfFilePath);
					//pdf.RasterizeToImageFiles(outputFilePath, new int[] { 1 }, 2048, 2048, IronPdf.Imaging.ImageType.Png, 600);
					pdf.RasterizeToImageFiles(outputFilePath, new int[] { 1 }, IronPdf.Imaging.ImageType.Png, dpi);
				}
				else if (format == "jpg") {
					var pdf = IronPdf.PdfDocument.FromFile(pdfFilePath);
					//pdf.RasterizeToImageFiles(outputFilePath, new int[] { 1 }, 2048, 2048, IronPdf.Imaging.ImageType.Jpeg, 600);
					pdf.RasterizeToImageFiles(outputFilePath, new int[] { 1 }, IronPdf.Imaging.ImageType.Jpeg, dpi);
				}
			});

			// return still in progress
			return new CreateCertificateResponse()
			{
				Data = new CreateCertificateState()
				{
					MetadataHash = metadataHash
				}
			};
		}

		private static int MaxDPIForResolution(float paperWidth, float paperHeight, int imageMaxWidth, int imageMaxHeight)
		{
			float maxWidthDPI = imageMaxWidth / (paperWidth / 25.4f);
			float maxHeightDPI = imageMaxHeight / (paperHeight / 25.4f);
			return (int)Math.Min(maxWidthDPI, maxHeightDPI);
		}

		private static string SubstituteCertificateHtml(string certficateSlug, string language, UserCertificateMetadataDto userCertificateMetadata, string metadataHash)
		{
			string html = null;
			try
			{
				var path = (CertificatePath + "/" + certficateSlug + $"/html/index.{language}.html").MapServerPath();
				html = File.ReadAllText(path);
			}
			catch
			{
				return null;
			}

			if (userCertificateMetadata == null) return html;

			var properties = typeof(UserCertificateMetadataDto).GetProperties();
			foreach (var property in properties)
			{
				var value = property.GetValue(userCertificateMetadata);
				if (value == null) continue;

				string valueStr = null;
				if (value is DateTime) valueStr = ((DateTime)value).ToString("d. M. yyyy");
				else if (value is DateTimeOffset) valueStr = ((DateTimeOffset)value).ToString("d. M. yyyy");
				else valueStr = value.ToString();

				html = html.Replace("###" + property.Name + "###", valueStr);
			}

			if (metadataHash != null) {
				html = html.Replace("###MetadataHash###", metadataHash);
				html = html.Replace("###MetadataHashShort###", metadataHash.Substring(0, 8));
			}

			return html;
		}

		private static string CreateOutputCertificateFilePath(string hash, string format, string certificateSlug = null)
		{
			if (hash == null && certificateSlug == null)
				throw new ArgumentNullException(nameof(hash) +"," + nameof(certificateSlug));
			return hash != null && hash != certificateSlug
				? $"{CertificateOutputPath.MapServerPath()}\\{DateTime.UtcNow.ToString("yyyy_MM")}\\{hash}.{format}"
				: CreateOutputCertificateBaseFilePath(certificateSlug, format);
		}

		private static string CreateOutputCertificateBaseFilePath(string hash, string format)
		{
			if (hash == null) throw new ArgumentNullException(nameof(hash));
			return $"{CertificateOutputPath.MapServerPath()}\\{hash}.{format}";
		}

		private UserCertificateDto GetUserCertificate(int userCertificateId, string applicationSlug, string sessionId)
		{
			var getUserCertificate = new GetUserCertificate()
			{
				Id = userCertificateId,
				ApplicationSlug = applicationSlug,
				SessionId = sessionId,
				RequestOrigin = Configuration.GetCurrentServiceUrl(),
			};
			var response = this.GetMessage<GetUserCertificate, GetUserCertificateResponse>(getUserCertificate, Configuration.GetServiceUrl(ServiceNames.ContentService))?.GetBody();
			return response?.Data;
		}

		private CertificateDto GetCertificate(string certificateSlug, string applicationSlug)
		{
			var getCertificate = new GetCertificate()
			{
				CertificateSlug = certificateSlug,
				ApplicationSlug = applicationSlug,
				RequestOrigin = Configuration.GetCurrentServiceUrl(),
			};
			var response = this.GetMessage<GetCertificate, GetCertificateResponse>(getCertificate, Configuration.GetServiceUrl(ServiceNames.ContentService))?.GetBody();
			return response?.Data;
		}

		private string ValidateFormat(string format)
		{
			if (format == null) return null;
			var formartLower = format.ToLower();
			return formartLower != "pdf"
				&& formartLower != "png"
				&& formartLower != "jpg"
				? null : formartLower;
		}
	}
}