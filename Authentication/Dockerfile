FROM mcr.microsoft.com/dotnet/core/aspnet:3.1-buster-slim AS base
WORKDIR /app
EXPOSE 5001

#ENV ASPNETCORE_Kestrel__Certificates__Default__Password="Test"
#ENV ASPNETCORE_Kestrel__Certificates__Default__Path="WsPc70.pfx"
#ENV ASPNETCORE_Kestrel__Endpoints__HttpsInlineCertFile__Certificate__Path="WsPc70.pfx"
#ENV ASPNETCORE_Kestrel__Endpoints__HttpsInlineCertFile__Certificate__Password="Test"
#ENV ASPNETCORE_Kestrel__Endpoints__HttpsInlineCertFile__Url="https://ws-pc-70:5001"
ENV ASPNETCORE_Kestrel__Endpoints__Http__Url="http://ws-pc-70:5001"
ENV ASPNETCORE_URLS=http://+:5001
#ENV ASPNETCORE_HTTPS_PORT=5001
ENV ConnectionStrings__TestDb="Data Source=172.20.0.2;Database=Identity;User Id=sa;Password=gjkjcfnbrA1$;"
ENV ServiceUrls__AuthorityApiEndpoint="http://ws-pc-70:5001"
ENV ServiceUrls__WebApiEndpoint="http://ws-pc-70:5007"
ENV ServiceUrls__DefaultRedirectUri="http://ws-pc-70:5005"
ENV ServiceUrls__ExtAppRedirectUri="http://ws-pc-70:5008"
ENV ServiceUrls__CertificateName="WsPc70.pfx"

FROM mcr.microsoft.com/dotnet/core/sdk:3.1-buster AS build
WORKDIR /src
COPY ["Authentication.csproj", "./"]


RUN dotnet restore "./Authentication.csproj"

COPY . .

WORKDIR "/src/."

RUN dotnet build "Authentication.csproj" -c Release -o /app

FROM build AS publish
RUN dotnet publish "Authentication.csproj" -c Release -o /app


COPY ["WsPc70.pfx", "/app/WsPc70.pfx"]
COPY ["MyBase64.cer", "/app/MyBase64.cer"]
#RUN update-ca-certificates

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "Authentication.dll"]