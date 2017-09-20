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
 * PHP Escaper
 * Context Escaper based on OWASP XSS Prevention, implemented in PHP. Please refer here:
 * https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet
 * From Rule #0 to Rule #5.
 *
 * Class Escaper
 * @author  Gabriel Lucernas Pascual (ghabxph) <ghabxph@gmail.com>
 * @version 1.0.1
 * @since   2017.09.17
 */
class Escaper
{
    /**
     * Converts untrusted input a safe HTML Element Content as
     * stated in XSS Prevention Cheat Sheet - Rule #1
     * @param string $sContent
     * @return Returns safe HTML Element Content
     */
    public static function htmlElementContent($sContent)
    {
        /**
         * OWASP Specification:
         * Escape:
         * & --> &amp;
         * < --> &lt;
         * > --> &gt;
         * " --> &quot;
         * ' --> &#x27;
         * / --> &#x2F;
         */
        return htmlspecialchars($sContent, ENT_QUOTES);
    }
    
    /**
     * Converts untrusted input into a safe HTML Common Attribute
     * as stated in XSS Prevention Cheat Sheet - Rule #2
     * @param string $sAttributeValue
     * @return Returns safe HTML Common Attribute
     */
    public static function htmlCommonAttribute($sAttributeValue)
    {
        /**
         * OWASP SPECIFICATION:
         * Except for alphanumeric characters, escape all characters
         * with ASCII values less than 256 with the &#xHH; format 
         * (or a named entity if available) to prevent switching out
         * of the attribute.
         */
        $aEncoded = array_filter(explode('-', chunk_split(bin2hex($sAttributeValue), 2, '-')));
        return implode(array_map(function($sHex) {
            $sPattern   = '&#x%s;';
            $sWhiteList = 'a-z0-9';
            $sChar      = hex2bin($sHex);
            $bIsMatch   = preg_match('/[' . $sWhiteList . ']/i', $sChar) === 1;
            
            return ($bIsMatch === true) ? $sChar : sprintf($sPattern, $sHex);
        }, $aEncoded));
    }
    
    /**
     * Converts untrusted input into a safe javascript data value.
     * Make sure to quote the output first as stated in XSS Prevention Cheat Sheet - Rule #3.
     * @param string $sJsValue
     * @return Returns safe javascript data value
     */
    public static function javascriptDataValue($sJsValue)
    {
        /**
         * OWASP SPECIFICATION:
         * Except for alphanumeric characters, escape all characters
         * less than 256 with the \xHH format to prevent switching
         * out of the data value into the script context or into
         * another attribute.
         */
        $aEncoded = array_filter(explode('-', chunk_split(bin2hex($sJsValue), 2, '-')));
        return implode(array_map(function($sHex) {
            $sPattern   = '\\x%s';
            $sWhiteList = 'a-z0-9';
            $sChar      = hex2bin($sHex);
            $bIsMatch   = preg_match('/[' . $sWhiteList . ']/i', $sChar) === 1;
            
            return ($bIsMatch === true) ? $sChar : sprintf($sPattern, $sHex);
        }, $aEncoded));
    }
    
    /**
     * Converts untrusted input into a safe CSS property value as
     * stated in XSS Prevention Cheat Sheet - Rule #4.
     * @param string $sCssValue
     * @return Returns safe CSS property value
     */
    public static function cssValue($sCssValue)
    {
        /**
         * OWASP SPECIFICATION:
         * Except for alphanumeric characters, escape all characters with ASCII
         * values less than 256 with the \HH escaping format.
         *
         * CSS escaping supports \XX and \XXXXXX. Using a two character escape
         * can cause problems if the next character continues the escape sequence.
         * There are two solutions
         *    (a) Add a space after the CSS escape (will be ignored by the CSS
         *    parser)
         *    (b) use the full amount of CSS escaping possible by zero padding
         *    the value.
         *
         * Developer Note:
         *   I will implement \XX scheme, therefore, in every escaped characters,
         *   I will add an additional space to solve the CSS Escaping Problem.
         *
         */
        $aEncoded = array_filter(explode('-', chunk_split(bin2hex($sCssValue), 2, '-')));
        return implode(array_map(function($sHex) {
            $sPattern   = '\\%s ';
            $sWhiteList = 'a-z0-9';
            $sChar      = hex2bin($sHex);
            $bIsMatch   = preg_match('/[' . $sWhiteList . ']/i', $sChar) === 1;
            
            return ($bIsMatch === true) ? $sChar : sprintf($sPattern, $sHex);
        }, $aEncoded));
    }
    
    /**
     * Converts untrusted input into a safe URL Parameter Value as
     * stated in XSS Prevention Cheat Sheet - Rule #5
     * @param string $sParameterValue
     * @return Returns safe URL Parameter Value
     */
    public static function urlParameterValue($sParameterValue)
    {
        /**
         * OWASP SPECIFICATION:
         * Except for alphanumeric characters, escape all characters
         * with ASCII values less than 256 with the %HH escaping format.
         */
        $aEncoded = array_filter(explode('-', chunk_split(bin2hex($sParameterValue), 2, '-')));
        return implode(array_map(function($sHex) {
            $sPattern   = '%s';
            $sWhiteList = 'a-z0-9';
            $sChar      = hex2bin($sHex);
            $bIsMatch   = preg_match('/[' . $sWhiteList . ']/i', $sChar) === 1;
            
            return ($bIsMatch === true) ? $sChar : '%' . sprintf($sPattern, $sHex);
        }, $aEncoded));
    }

    /**
     * JSON Encodes the variable securely
     * @param mixed   $mVariable
     * @return string Returns string containing xss safe string that can be displayed
     *                safely to the browser.
     */
    public static function secureJsonEncode($mVariable)
    {
        if (class_exists('VariableHtmlEscaper') === false)) {
            include_once('VariableHtmlEscaper.php');
        }
        return json_encode(VariableHtmlEscaper::doEscape($mVariable));
    }
}
