# Escaper
Context Escaper based on OWASP XSS Prevention, implemented in PHP. Please refer here:
https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet
From Rule #0 to Rule #5.

# Table of Contents
 1. [Before Using This Library](#before-using-this-library)
 
    1.1 [Rule #0 - Never Insert Untrusted Data Except in Allowed Locations](#rule-0---never-insert-untrusted-data-except-in-allowed-locations)
    
    1.2 [Rule #1 - HTML Escape Before Inserting Untrusted Data into HTML Element Content](#rule-1---html-escape-before-inserting-untrusted-data-into-html-element-content)
    
    1.3 [Rule #2 - Attribute Escape Before Inserting Untrusted Data into HTML Common Attributes](#rule-2---attribute-escape-before-inserting-untrusted-data-into-html-common-attributes)
    
    1.4 [Rule #3 - JavaScript Escape Before Inserting Untrusted Data into JavaScript Data Values](#rule-3---javascript-escape-before-inserting-untrusted-data-into-javascript-data-values)
        
       1.4.1 [BEWARE THAT](#beware-that)
    
    1.5 [Rule #4 - CSS Escape And Strictly Validate Before Inserting Untrusted Data into HTML Style Property Values](#rule-4---css-escape-and-strictly-validate-before-inserting-untrusted-data-into-html-style-property-values)
    
       1.5.1 [BEWARE THAT](#beware-that-1)
    
    1.6 [Rule #5 - URL Escape Before Inserting Untrusted Data into HTML URL Parameter Values](#rule-5---url-escape-before-inserting-untrusted-data-into-html-url-parameter-values)

 2. [Functions](#functions)
 
 3. [How to use?](#how-to-use)
    

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
`htmlElementContent($sContent)` (since v1.0)

Converts untrusted input a safe HTML Element Content as stated in Rule #1

`htmlCommonAttribute($sAttributeValue)` (since v1.0)

Converts untrusted input into a safe HTML Common Attribute as stated in Rule #2


`javascriptDataValue($sJsValue)` (since v1.0)

Converts untrusted input into a save javascript data value. Make sure to quote the output first as stated in Rule #3. 


`cssValue($sCssValue)` (since v1.0)

Converts untrusted input into a safe CSS property value as stated in Rule #4.


`urlParameterValue($sParameterValue)` (since v1.0)

Converts untrusted input into a safe URL Parameter Value as stated in Rule #5


`secureJsonEncode` (since v1.0.1)

Recursively escapes all string that a php variable contain, and converts it into a json string that is XSS safe.

# How to use?
 1. Download the files at [releases](https://github.com/ghabxph/Escaper/releases) here in github.
 2. As of the moment, you need these files:
    * Escaper.php
    * VariableHtmlEscaper.php
    Include the following folders mentioned somewhere in your project folder.
 3. Include Escaper.php
 
 
 ```php
include_once 'Escaper.php';

// Escape untrusted input based on context
Escaper::htmlElementContent('... untrusted input here ...');
Escaper::htmlCommonAttribute('... untrusted input here ...');
Escaper::javascriptDataValue('... untrusted input here ...');
Escaper::cssValue('... untrusted input here ...');
Escaper::urlParameterValue(' ... untrusted input here ...');
Escaper::secureJsonEncode($mAnyValueHere);
```
 
 # In the future
 In the future, I shall make this a composer project, so that adding this work as a project dependency of yours would be more easier and portable.
