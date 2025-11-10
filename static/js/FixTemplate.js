/*!
 * FastFileLink - Template Fixes
 * https://github.com/nuwainfo/ffl
 *
 * Licensed under the Apache-2.0 license
 *
 * Utility to fix HTML attributes lost during template processing
 *
 * See LICENSE file in the project root for full license information.
 */

var $j = jQuery;

// Fix img tag attributes lost after pluginize.
// =============================================================================

var findComments = function(el) {
    var arr = [];
    for(var i = 0; i < el.childNodes.length; i++) {
        var node = el.childNodes[i];
        if(node.nodeType === 8) {
            arr.push(node);
        } else {
            arr.push.apply(arr, findComments(node));
        }
    }
    return arr;
};

var walkDOM = function (node, tag) {
        if(node.nodeName.toUpperCase() == tag.toUpperCase()){
            return node
        };
        node = node.firstChild;
        while(node) {
            var result = walkDOM(node, tag);
            if (result){
                return result;
            };
            node = node.nextSibling;
        };
};    

var findTargetNode = function(commentNodes, commentStr, tag){
    var target;
    for(i in commentNodes){
        if(commentNodes[i].nodeValue == commentStr){
            node = commentNodes[i].nextSibling;
            while(node){
                var result = walkDOM(node, tag);
                if (result){
                    return result;
                } else {
                    node = node.nextSibling
                };
            };
        };
    };
    return null;
};

var addAttrs = function(target, attrs){
    $target = $j(target);
    for(k in attrs){
        if(k == 'class'){
            var origin = $target.attr('class');
            $target.attr('class', origin + ' ' + attrs[k]);
        }else{
            $target.attr(k, attrs[k]);
        };
    };
};

$j(document).ready(function() {
    var commentNodes = findComments(document);
    
    // Add Attr to tag
    if(!typeof(__cms_context) == 'undefined') {
        for(var placeholderId in __cms_context) {
            var commentList = findTargetNode(
                commentNodes, placeholderId, 
                __cms_context[placeholderId]['tag']);
            if(commentList != null){ 
                addAttrs(commentList, __cms_context[placeholderId]['attrs'])
            };
        };
    };
});

// =============================================================================

// Fix Django CMS edit mode issues #2792.
// =============================================================================

$j(document).ready(function() {
    var toAppendDiv = $j('div.cms-placeholder');  
    $j('._cmsCollection').append(toAppendDiv);  
    var toAppendScript = $j("script[id|='cms-plugin-child-classes']");  
    $j('._cmsCollection').append(toAppendScript);
    
    var commentNodes = findComments(document);
    
    for(var j = 0;j < commentNodes.length; j++) {
        if (commentNodes[j].nodeValue.substring(
            0, 'FixCMS:cmsboilerplatetagstart='.length
            ) == 'FixCMS:cmsboilerplatetagstart=') {
            var placeholderId = commentNodes[j].nodeValue.substring(
                'FixCMS:cmsboilerplatetagstart='.length);
            var p = null;
            var next = commentNodes[j].nextSibling;
            while(!p && next){
                if(next.nodeName.toUpperCase() == 'P') {
                    var p = next;
                } else {
                    next = next.nextSibling;
                }
            };
            
            if(p){
                var jp = $j(p);
                
                var comment = null;
                var next = p;
                var tagList = [];
                while((! comment) && (next)){
                    next = next.nextSibling;
                    if (next){
                        if(next.nodeValue == 
                            'FixCMS:cmsboilerplatetagend=' + placeholderId) {
                            comment = next;
                        } else {
                            tagList.push(next);
                        };
                    };
                };
                
                if (comment) {
                    for(var i = 0;i < tagList.length; i++) {
                        p.appendChild(tagList[i]);
                    };   
                    
                    var lastChild = jp.children().last();
                    if($j.trim(lastChild.html()) == '' & 
                       lastChild.prop("tagName") == 'P') {
                        lastChild.remove();
                    };
                };
            };  
        };
    };
});

// =============================================================================

// Fix template use js to render link #2982.
// =============================================================================
$j(document).ready(function() {
    var allLink = $j('link, script').each(function(index) { 
        var tag = $j(this);
        
        if (tag.prop("tagName") == 'LINK') {
            var href = tag.attr('href');
        } else {
            var href = tag.attr('src');
        };
        
        if (href != undefined) {
            if(!(href.substring(0, CMS_STATIC.length) == CMS_STATIC) & 
               !(href.substring(0, 4).toLowerCase() == "http") &
               !(href.substring(0, 2).toLowerCase() == "//")) {
                if(href.substring(0, 1) == "/") {
                    var newHref = CMS_STATIC + href.substring(1);
                } else {
                    var newHref = CMS_STATIC + href;
                };
                
                $j.ajax({url: newHref, success: function(result) {
                    if (tag.prop("tagName") == 'LINK'){
                        tag.attr('href', newHref);
                    } else {
                        tag.attr('src', newHref);
                    };
                }});
            };
        };
    });
});
// =============================================================================


// Fix plugin rebuild error after edit any plugin in some templates by reload page #.
// =============================================================================
jQuery(document).ready(function() {
    let CMS = window.CMS || {};
    const promiseCMS = new Promise((resolve, reject) => {
      const loop = () => !jQuery.isEmptyObject(CMS) ? resolve(CMS) : setTimeout(loop)
      loop();
    });

    promiseCMS.then((value) => {
        CMS.$.ajaxSetup({
            beforeSend: function() {
                // show loading dialog // works
            },
            complete: function(xhr, stat) {
                // hide dialog // works
            },
            success: function(result, status, xhr) {
                // not showing the alert
                let url = CMS.$(this)[0].url;
                let reg = /admin\/cms\/placeholder\/object\/[0-9]+\/edit\/[0-9]+/g;

                if (url.match(reg)) {
                    location.reload()
                }
            }
        });

    });
});
// =============================================================================