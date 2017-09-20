<?php
/**
 * Copyright 2017 (c) ghabxph
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies
 * or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
 * FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * TEST USAGE.
 * This PHP File is intended to demonstrate to you how escaper escape things according to it's context:
 *   * Context as CSS
 *   * Context as Javascript
 *   * Context as HTML
 *   * Context as HTML Attribute
 *   * Context as JSON (Keys and Values are Escaped as HTML)
 */
?>
<?php include_once('Escaper.php') ?>
<html>
<head>
	<title>Test XSS</title>
	<style>
		* {
			/** We guard it with cssValue() method (implemented in escaper) */
			font-family: '<?php echo Escaper::cssValue('</style><script>alert(\'xss\')</script>') ?>';
		}
		.tdPadding {
			padding: 5px;
		}
	</style>
</head>
<body>
	<h1>Demonstrating Vulnerability</h1>
	<div class="<?php echo Escaper::htmlCommonAttribute('" onclick=alert(String.fromCharCode(88,83,83)) xssed="xssed'); ?>">
		<?php echo Escaper::htmlElementContent('<script>alert(\'xss\')</script>') ?>
		<a href="?doThis=<?php echo Escaper::urlParameterValue('I will hack you<script>alert(\'xss boi\')</script>&anotherRequest=youn00b') ?>" class="something"></a>
	</div>
	<div>
		<b>Echoing your GET Requests</b><br>
		<table border="1">
			<thead>
				<tr>
					<th class="tdPadding">Key</th>
					<th class="tdPadding">Value</th>
				</tr>
			</thead>
			<tbody>
				<?php foreach($_GET as $sKey => $sValues) { ?>
					<tr>
						<td class="tdPadding"><?php echo Escaper::htmlElementContent($sKey); ?><br></td>
						<td class="tdPadding"><?php echo Escaper::htmlElementContent($sValues); ?><br></td>
					</tr>
				<?php } ?>
				
			</tbody>
		</table><br>
		<b>Testing secureJsonEncoder()</b><br>
		<b>Test #1</b><br>
		<pre><?php echo Escaper::secureJsonEncode('<script>alert(\'xss\')</script>') ?></pre>
		<b>Test #2</b><br>
		<pre><?php echo Escaper::secureJsonEncode([
			'abc' => 'vaaaa<script>alert(\'xss\')</script>'
		]) ?></pre>
		<b>Test #3</b><br>
		<pre><?php echo Escaper::secureJsonEncode([
			'abc' => [
				'abc' => [
					'abc' => 'vaaaa<script>alert(\'xss\')</script>'
				]
			],
			'<script>alert(\'xss\')</script>',
			'goddamnit'
		]) ?></pre>
		<b>Test #4</b><br>
		<pre><?php echo Escaper::secureJsonEncode(55) ?></pre>
		<b>Test #5</b><br>
		<pre><?php echo Escaper::secureJsonEncode([1,2,3,'<script>alert(\'xss\')</script>']) ?></pre>
		<b>Test #6</b><br>
		<pre><?php echo Escaper::secureJsonEncode(['<script>alert(\'xzz\')</script>'=>55]) ?></pre>
		
	</div>
	<script
		src="https://code.jquery.com/jquery-3.2.1.js"
		integrity="sha256-DZAnKJ/6XZ9si04Hgrsxu/8s717jcIzLy3oi35EouyE="
		crossorigin="anonymous"></script>
	<script>
		$(function(){
			$('.something').text('<?php echo Escaper::javascriptDataValue('\');});document.write(\'hacked by haxxooor\')') ?>');
		});
	</script>
</body>
</html>
