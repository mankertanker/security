#######################################
# SETUP CREDS FOR GRAYLOG             #
#######################################  
$password = "blacklister"
$username = "blacklister"
$pair = "${username}:${password}"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)
$basicAuthValue = "Basic $base64"
$Headers = @{ Authorization = $basicAuthValue }
$Database = 'dsdb.cfs.local'
$tptoken = 'MTYyOk9lZm5rV3pJRERKWmQ5c2hwWGJHNzJscVU4RlJ1RmFTQjZMa25mbDZnWnM9'
##################################
# TRUST SELF SIGNED CERTIFICATES #
##################################
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12  
####################
#  Start TP Ticket #     
####################
$start_ticket = {

    $rest = Invoke-RestMethod -Uri https://carsforsale.tpondemand.com/api/v1/Projects/80514/UserStories?where=%28Tags%20eq%20%22$dealerid%22%29"&"access_token=$tptoken -Method Get -ContentType 'application/json' 
    $rest = $rest.Items 
    Start-Sleep -Seconds 2

    $state = $rest.EntityState.Name
    $fields = @($rest.CustomFields) 
    $priority = $fields[1].Value


    if($rest){
     if(($priority -eq "High"))
     {
        echo "Ticket Exists or Being Worked on"
     }
     else
     {
        echo "Create TICKET 1" 
        &$create_ticket
      }
    }
    elseif (!$rest)
    {
         echo "Create TICKET 2" 
         &$create_ticket

    }
    else
    {
        echo " No Work"
    }
}

 $create_ticket = {
             
        Write-Output "no ticket created for $dealerid"
        Write-Output "starting TP actions"
        Start-Sleep -Seconds 4
    
        # Grab Mobile Numbers from the account
        $sqlquery = Invoke-Sqlcmd -Query "select top 50 MobilePhone from LoginAttempt a inner join dealeruser b on a.DealerUserID = b.UserID where dealerid in('$dealerid') order by loginid desc" -ServerInstance $Database | Group-Object MobilePhone | Sort-Object -Property Count -Descending | Select-Object Name
        $numbers = Write-Output $sqlquery | Select-Object Name -ExpandProperty Name

        # Grab basic dealer information for the ticket
        $dealerinfo = Invoke-Sqlcmd -Query "select LocationName, DisplayName, Address1, City, State, CountryCode, Phone from DealerLocation where dealerid in('$dealerid')" -ServerInstance $Database | Out-String

        # Grab Dealer's Website
        $dealer_website = Invoke-Sqlcmd -Query "select top 100 DomainName from DealerDomain where dealerid in('$dealerid') AND IsPrimary=1" -ServerInstance $Database
        $dealer_website = $dealer_website.DomainName

        # Grab login history for the account
        $login_info = Invoke-Sqlcmd -Query "select top 50 a.datecreate, a.username, a.wasSuccessful, a.ipaddress from LoginAttempt a inner join dealeruser b on a.DealerUserID = b.UserID where dealerid in('$dealerid') order by loginid desc" -ServerInstance $Database | ConvertTo-Html

        # Grab API Calls for the past day and a half
        $post_data_ApiCall = Invoke-RestMethod -Method Get -Uri https://graylog-cluster.carsforsale.local:443/api/search/universal/relative/terms?field=ApiCall"&"query=%22$dealerid%22"&"size=25"&"range=125000"&"filter=streams%3A5978df67041f63048180339b -Headers $Headers
        $post_data_ApiCall = $post_data_ApiCall.terms 
        $checker = $post_data_ApiCall | Get-Member -MemberType NoteProperty
        if(!$checker)
        {echo "TEST API CALL"
        $post_data_ApiCall = $null}
        else{echo "value API CALL"
        $post_data_ApiCall | Add-Member "API" -NotePropertyValue "Total"
        $post_data_ApiCall = $post_data_ApiCall | ConvertTo-Html
        }

        # Grab the host addresses making the API Calls
        $post_data_HostAddress = Invoke-RestMethod -Method Get -Uri https://graylog-cluster.carsforsale.local:443/api/search/universal/relative/terms?field=HostAddress"&"query=%22$dealerid%22"&"size=25"&"range=125000"&"filter=streams%3A5978df67041f63048180339b -Headers $Headers
        $post_ips = $post_data_HostAddress.terms | Select-String -pattern "\d{1,3}(\.\d{1,3}){3}" -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique
        $post_ips = $post_ips -replace "^192.168.*|^66.231.5.*",""
        $post_ips = $post_ips | Select-String -Pattern "\d{1,3}(\.\d{1,3}){3}" -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique
        $post_data_HostAddress = $post_data_HostAddress.terms
        $checker = $post_data_HostAddress | Get-Member -MemberType NoteProperty
        if(!$checker)
        {echo "TEST HOSTADDRESS"
        $post_data_HostAddress = $null}
        else{echo "VALUE HOSTADDRESS"
        $post_data_HostAddress | Add-Member "Context" -NotePropertyValue "Total"
        $post_data_HostAddress = $post_data_HostAddress | ConvertTo-Html
        }

        # Grab Signin Context
        $post_data_Signin = Invoke-RestMethod -Method Get -Uri https://graylog-cluster.carsforsale.local:443/api/search/universal/relative/terms?field=context"&"query=%22$dealerid%22"&"size=25"&"range=125000"&"filter=streams%3A5ac3c2db3756a80b9015c611 -Headers $Headers
        $post_data_Signin = $post_data_Signin.terms 
        $checker = $post_data_Signin | Get-Member -MemberType NoteProperty
        if(!$checker)
        {echo "TEST SIGNIN"
        $post_data_Signin = $null}
        else{echo "VALUE SIGNIN"
        $post_data_Signin | Add-Member "Context" -NotePropertyValue "Total"
        $post_data_Signin = $post_data_Signin | ConvertTo-Html
        }

        # Get ipinfo from login history
        $iplogininfo = Invoke-Sqlcmd -Query "select top 50 a.datecreate, a.username, a.wasSuccessful, a.ipaddress from LoginAttempt a inner join dealeruser b on a.DealerUserID = b.UserID where dealerid in('$dealerid') order by loginid desc" -ServerInstance 'dsdb.cfs.local' | Format-Table | Out-String -Width 160

        $ipinfo_ipaddresses = $iplogininfo | Select-String -pattern "\d{1,3}(\.\d{1,3}){3}" -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique
        $ipinfo_ipaddresses = $ipinfo_ipaddresses -replace "^10.1.*|^10.2.*",""
        $ipinfo_ipaddresses = $ipinfo_ipaddresses | Select-String -pattern "\d{1,3}(\.\d{1,3}){3}" -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique 

        # Grab Mobile Activity
        $post_data_mobile = Invoke-RestMethod -Method Get -Uri https://graylog-cluster.carsforsale.local:443/api/search/universal/relative/terms?field=GEOIP"&"query=%22$dealerid%22"&"size=25"&"range=125000"&"filter=streams%3A5b57859d3c44de430f44e563 -Headers $Headers
        $mobile_ips = $post_data_mobile.terms | Select-String -pattern "\d{1,3}(\.\d{1,3}){3}" -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique
        $mobile_ips = $mobile_ips -replace "^192.168.*|^66.231.5.*",""
        $mobile_ips = $mobile_ips | Select-String -Pattern "\d{1,3}(\.\d{1,3}){3}" -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique
        $post_data_mobile = $post_data_mobile.terms
        $checker = $post_data_mobile | Get-Member -MemberType NoteProperty
        if(!$checker)
        {echo "TEST MOBILE DATA"
        $post_data_mobile = $null}
        else{"VALUE MOBILE DATA"
        $post_data_mobile | Add-Member "Mobile IPs" -NotePropertyValue "Total"
        $post_data_mobile = $post_data_mobile | ConvertTo-Html
        }
       
        #########################
        # IP ADDRESS INFO CALLS #
        #########################

        foreach($line in $ipinfo_ipaddresses){
            $curlinfo = Invoke-WebRequest -UseBasicParsing -Uri https://ipinfo.io/"$line"?token=3e2ce493d62310
            $run = $curlinfo | ConvertFrom-Json | ConvertTo-Html
            #$run = "<li> $curlinfo.Content </li>"
            $got += $run
        }
        foreach($line in $post_ips){
            $post_curlinfo = Invoke-WebRequest -UseBasicParsing -Uri https://ipinfo.io/"$line"?token=3e2ce493d62310
            $post_ipinfolist = $post_curlinfo | ConvertFrom-Json | ConvertTo-Html
            #$post_ipinfolist = "<li> $post_curlinfo.Content </li>"
            $go += $post_ipinfolist
        }
        $go = $go -replace '{"ip": "66.231.5.130.*}',""
        foreach($line in $mobile_ips){
            $mobile_curlinfo = Invoke-WebRequest -UseBasicParsing -Uri https://ipinfo.io/"$line"?token=3e2ce493d62310
            $mobile_ipinfolist = $mobile_curlinfo | ConvertFrom-Json | ConvertTo-Html
            #$mobile_ipinfolist = "<li> $mobile_curlinfo.Content </li>"
            $phone += $mobile_ipinfolist
        }
        # Potential Other accounts that the bad ip has logged into
        $sqliplogin = Invoke-Sqlcmd -Query "select top 50 a.DateCreate, a.username, a.wasSuccessful, b.dealerid, a.IPAddress from LoginAttempt a inner join dealeruser b on a.DealerUserID = b.UserID where ipaddress in('$ipaddress') order by loginid desc" -ServerInstance $Database | ConvertTo-HTML

        ######################
        # Teams Alert        #
        ######################

        $uri = 'https://carsforsale.webhook.office.com/webhookb2/6f743742-716d-4b00-b9f1-0e1b3d176c0e@93452f48-4c53-4750-889d-927debbcdd09/IncomingWebhook/d51bf3aa8c18491da02e26989afa8e32/f086e6d9-a5d5-4d8a-bf0d-8cdd3577c9a3'

        $JSON = @{
            "@type"    = "MessageCard"
            "@context" = "<http://schema.org/extensions>"
            "title"    = "Unknown Poster $dealerid"
            "text"     = "unknown_poster.ps1"
            "sections" = @(
            @{
            "activityTitle"    = 'Ticket has been Created in Target Process'
            "activitySubtitle" = "$dealer_website"
            "activityText"     = "$dealerinfo"
              }
             )
            } | ConvertTo-JSON

         $Params = @{
            "URI"         = $uri
            "Method"      = 'Post'
            "Body"        = $JSON
            "ContentType" = 'application/json'
            }

         Invoke-RestMethod @Params

        #######################
        #  Create TP Ticket   #
        #######################

        # Desscription most be written in HTML

        $desc = "<h2> The following account $dealerid has been tagged for deactivation</h2>
            <h3>Dealership:</h3>
            <p>$dealerinfo</p>
            <h3>Dealer Website:</h3>
            <div>https://$dealer_website</div>
            <h3>API Calls:</h3>
            <div>$post_data_ApiCall</div>
            <h3>HostAddresses:</h3>
            <div>$post_data_HostAddress</div>
            <h3>API IP Addresses:</h3>
            <div>$go</div>
            <h3>Signin Calls:</h3>
            <h5>$post_data_Signin</h5>
            <h3>Other Potential Accounts:</h3>
            <div>$sqliplogin</div>
            <h3>Login Info:</h3>
            <div>$login_info</div>    
            <h3>IP Information:</h3>
            <div>$got</div>
            <h3>Mobile Section</h3>
            <div>$post_data_mobile</div>
            <h3>Mobile IP Info</h3>
            <div>$phone</div> "

        $body = @{
        Name = "Unknown Poster $dealerid"
        Tags = "$dealerid"
        Project = @{Id = 80514}
        Team = @{Id = 80515}
        Description = "$desc"
        CustomFields = @(
        @{Name = 'Dealerid' 
        Value = "$dealerid"} 
        @{Name = 'Priority Level'
        Value = 'High'} 
        @{Name = 'Script' 
        Value = 'unknown_poster.ps1'})
        } | ConvertTo-Json

    
        Invoke-RestMethod -uri https://carsforsale.tpondemand.com/api/v1/UserStories?access_token=$tptoken -Method Post -ContentType "application/json" -Body $body
 }
     


#####################################################################################
# GO THROUGH EACH DEALER AND SEE IF THE POSTING IP HAS EVER LOGGED INTO THE ACCOUNT #
#####################################################################################
$catch_posters = {
    # GET POSTING IPS FOR DEALERID AND FORMAT OUTPUT
    $dealerid = $line
    Write-Output "#############################"
    Write-Output "#  STARTING FOR $dealerid   #"
    Write-Output "#############################"
    Start-Sleep -Seconds .5
    $graylogquery_posts = Invoke-RestMethod -Method Get -Uri http://10.3.55.16:9000/api/search/universal/relative/terms?field=HostAddress"&"query=ApiCall%3AaddNewInventory+AND+DealerId%3A$dealerid"&"size=1750"&"range=18000"&"filter=streams%3A5978df67041f63048180339b -Headers $Headers 
    $graylogquery_posts = $graylogquery_posts.terms
    $graylogquery_posts = $graylogquery_posts | Out-String
    $graylogquery_posts = $graylogquery_posts -replace ", 192.168.*", ""
    $graylogquery_posts = $graylogquery_posts | Select-String -pattern "\d{1,3}(\.\d{1,3}){3}" -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value }
    $graylogquery_posts = $graylogquery_posts | Sort-Object -Unique
    # ECHO FORMATTED/SORTED OUTPUT
    $graylogquery_posts
    # GO THROUGH EACH IP POSTING AND DETERMINE IF IT HAS A LOGIN FOR THE ACCOUNT
    foreach($line in $graylogquery_posts){
        $ipaddress = $line
        $ipaddress
        if($ipaddress -match "66.231.5.*"){
            Write-Output "internal ip, doing nothing"
        }
        else{
            $check_login = Invoke-Sqlcmd -Query "select top 100 a.DateCreate, b.dealerid, a.username, a.IPAddress from LoginAttempt a inner join dealeruser b on a.DealerUserID = b.UserID where ipaddress in('$ipaddress') and dealerid in ('$dealerid') and a.wasSuccessful in ('True') order by loginid desc" -ServerInstance $Database
            if(!$check_login){
                Start-Sleep -Seconds 2
                echo "no login create ticket"
                &$start_ticket
            }
            elseif($check_login){
                Write-Output "logged in"
            }
            else{
                Write-Output "no worky"
            }
        }
        Start-Sleep -Seconds 1
    }

}
########################################
# GRAB INITIAL 40 TOP POSTING ACCOUNTS #
########################################
$graylogquery_posts = Invoke-RestMethod -Method Get -DisableKeepAlive -Uri http://10.3.55.16:9000/api/search/universal/relative/terms?field=DealerId"&"query=%22addNewInventory%22"&"size=1750"&"range=18000"&"filter=streams%3A5978df67041f63048180339b -Headers $Headers
$graylogquery_posts = $graylogquery_posts.terms
$graylogquery_posts

Start-Sleep -Seconds 2

$posts = Invoke-RestMethod -Method Get -DisableKeepAlive -Uri http://10.3.55.16:9000/api/search/universal/relative/terms?field=DealerId"&"query=%22addNewInventory%22"&"size=250"&"range=8000"&"filter=streams%3A5978df67041f63048180339b -Headers $Headers
$posts = $posts.terms
$posts

Start-Sleep -Seconds 2

# FORMAT RAW DATA INTO USEABLE PWSH OBJECTS
$graylogquery_posts = $graylogquery_posts | Out-String
$graylogquery_posts = $graylogquery_posts -split "`r`n"
$graylogquery_posts = $graylogquery_posts -replace ",","" 
$graylogquery_posts = $graylogquery_posts -replace "[:]","" | ConvertFrom-String -PropertyNames DealerId, Counts

# DISPLAY ACCOUNTS FROM TOP TO BOTTOM BY POST VOLUME
$sorted = $graylogquery_posts | Sort-Object -Property Counts -Descending
$sorted
$sorted = $sorted | Select-Object -First 40 | Select-Object -ExpandProperty DealerId -Property DealerId
####################################################################
# ITERATE THROUGH 40 TOP POSTING ACCOUNTS AND FIND ILLICIT POSTERS #
####################################################################
Start-Sleep -Seconds 2
foreach($line in $sorted){
    &$catch_posters
}



