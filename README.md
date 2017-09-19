# Escaper
Context Escaper based on OWASP XSS Prevention, implemented in PHP. Please refer here:
https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet
From Rule #0 to Rule #5.

# Before Using This Library:
Be sure to follow Rule #0 to Rule #5.

## Rule #0 - Never Insert Untrusted Data Except in Allowed Locations
```html
 <script>...NEVER PUT UNTRUSTED DATA HERE...</script>   directly in a script
 
 <!--...NEVER PUT UNTRUSTED DATA HERE...-->             inside an HTML comment
 
 <div ...NEVER PUT UNTRUSTED DATA HERE...=test />       in an attribute name
 
 <NEVER PUT UNTRUSTED DATA HERE... href="/test" />   in a tag name
 
 <style>...NEVER PUT UNTRUSTED DATA HERE...</style>   directly in CSS
```

## Rule #1 - HTML Escape Before Inserting Untrusted Data into HTML Element Content
```html
 <body>...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE...</body>
 
 <div>...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE...</div>
 
 any other normal HTML elements
```

## Rule #2 - Attribute Escape Before Inserting Untrusted Data into HTML Common Attributes
```html
 <div attr=...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE...>content</div>     inside UNquoted attribute
 
 <div attr='...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE...'>content</div>   inside single quoted attribute
 
 <div attr="...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE...">content</div>   inside double quoted attribute
```

## Rule #3 - JavaScript Escape Before Inserting Untrusted Data into JavaScript Data Values
```html
 <script>alert('...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE...')</script>     inside a quoted string
 
 <script>x='...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE...'</script>          one side of a quoted expression
 
 <div onmouseover="x='...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE...'"</div>  inside quoted event handler
```
### BEWARE THAT:
No matter how you escape this, XSS will always be possible here. So, you must put untrusted data with caution!
```html
 <script>
 window.setInterval('...EVEN IF YOU ESCAPE UNTRUSTED DATA YOU ARE XSSED HERE...');
 </script>
```

## Rule #4 - CSS Escape And Strictly Validate Before Inserting Untrusted Data into HTML Style Property Values
```html
 <style>selector { property : ...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE...; } </style>     property value

 <style>selector { property : "...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE..."; } </style>   property value

 <span style="property : ...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE...">text</span>         property value
```

### BEWARE THAT:
Some CSS contexts can never safely use untrusted data as input. EVEN IF PROPERLY CSS ESCAPED!
As for myself, I cannot reproduce this, but it must be possible that some browser allow this, so beware of this pithole.
```css
 { background : url("javascript:alert(1))"; }  // and all other URLs
 { text-size: "expression(alert('XSS'))"; }   // only in IE
```

## Rule #5 - URL Escape Before Inserting Untrusted Data into HTML URL Parameter Values
```html
<a href="http://www.somesite.com?test=...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE...">link</a >    
```

# Functions
`htmlElementContent($sContent)`

Converts untrusted input a safe HTML Element Content as stated in Rule #1

`htmlCommonAttribute($sAttributeValue)`

Converts untrusted input into a safe HTML Common Attribute as stated in Rule #2


`javascriptDataValues($sJsValue)`

Converts untrusted input into a save javascript data value. Make sure to quote the output first as stated in Rule #3. 


`cssValue($sCssValue)`

Converts untrusted input into a safe CSS property value as stated in Rule #4.


`urlParameterValue($sParameterValue)`

Converts untrusted input into a safe URL Parameter Value as stated in Rule #5

# How to use?
```php
include_once 'Escaper.php';

// Make instance
$oEscaper = new Escaper();

// Escape untrusted input based on context
$oEscaper->htmlElementContent('... untrusted input here ...');
$oEscaper->htmlCommonAttribute('... untrusted input here ...');
$oEscaper->javascriptDataValue('... untrusted input here ...');
$oEscaper->cssValue('... untrusted input here ...');
$oEscaper->urlParameterValue(' ... untrusted input here ...');
```
