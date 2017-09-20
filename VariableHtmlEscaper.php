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
 * Class VariableHtmlEscaper
 * This class is dedicated in HTML Escaping all string that a variable contains.
 * This basically scans the type of variable. If it is an array or object, it will nest itself
 * to find the key and value and HTML Encode it.
 * @author  Gabriel Lucernas Pascual (ghabxph) <ghabxph@gmail.com>
 * @version 1.0.1
 * @since   2017.09.20
 */
class VariableHtmlEscaper
{
    /**
     * HTML Escapes all string that a variable contains.
     * @param mixed   $mVariable
     * @return mixed  Returns variable containing xss safe string that can be encoded
     *                to JSON and be rendered to the browser securely.
     */
    public static function doEscape($mVariable)
    {
        if (class_exists('Escaper') === false) {
            include_once('Escaper.php');
        }
        $oInstance = new VariableHtmlEscaper();
        return $oInstance->escape($mVariable);
    }
    
    /**
     * Recursively escapes all string in the variable
     * @return mixed  Returns variable containing xss safe string that can be encoded
     *                to JSON and be rendered to the browser securely.
     */
    private function escape($mVariable)
    {
        if (is_string($mVariable) === true) {
            return Escaper::htmlElementContent($mVariable);
        }
        if (is_object($mVariable) === true) {
            return $this->escapeAsObject($mVariable);
        }
        if (is_array($mVariable) === true) {
            return $this->escapeAsArray($mVariable);
        }
        // Nothing to do. Since it's fine already. Assuming that the type is not dangerous.
        return $mVariable;
    }
    
    /**
     * Escapes as object
     * @return object
     */
    private function escapeAsObject($mVariable)
    {
        $mReturn = new stdClass;
        foreach ($mVariable as $mKey => $mValue) {
            if (is_string($mKey) === true) {
                $mKey = Escaper::htmlElementContent($mKey);
            }
            $mReturn->$mKey = $this->escape($mValue);
        }
        return $mReturn;
    }
    
    /**
     * Escapes as array
     * @return array
     */
    private function escapeAsArray($mVariable)
    {
        $mReturn = [];
        foreach ($mVariable as $mKey => $mValue) {
            if (is_string($mKey) === true) {
                $mKey = Escaper::htmlElementContent($mKey);
            }
            $mReturn[$mKey] = $this->escape($mValue);
        }
        return $mReturn;
    }
}
