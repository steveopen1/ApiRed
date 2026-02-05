const fs = require('fs');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;

// 辅助函数：获取代码上下文（前后各1行）
function getContextCode(code, loc) {
    if (!loc) return '';
    const lines = code.split(/\r?\n/);
    const startLine = Math.max(0, loc.start.line - 2); // loc.start.line is 1-based
    const endLine = Math.min(lines.length, loc.end.line + 1);
    // 添加行号前缀
    return lines.slice(startLine, endLine).map((line, idx) => {
        const lineNum = startLine + idx + 1;
        const prefix = lineNum === loc.start.line ? '> ' : '  ';
        return `${prefix}${lineNum}: ${line}`;
    }).join('\n');
}

// 辅助函数：尝试计算表达式的值
function evaluateExpression(node, scope, localBindings = {}) {
    if (!node) return null;

    // 0. 本地绑定优先 (函数参数)
    if (node.type === 'Identifier' && localBindings.hasOwnProperty(node.name)) {
        return localBindings[node.name];
    }

    // 1. 基础字面量
    if (node.type === 'StringLiteral') return node.value;
    if (node.type === 'NumericLiteral') return node.value;
    if (node.type === 'BooleanLiteral') return node.value;

    // 2. 模板字符串
    if (node.type === 'TemplateLiteral') {
        let result = '';
        for (let i = 0; i < node.quasis.length; i++) {
            result += node.quasis[i].value.raw;
            if (i < node.expressions.length) {
                const exprVal = evaluateExpression(node.expressions[i], scope, localBindings);
                result += (exprVal !== null ? exprVal : '${...}');
            }
        }
        return result;
    }

    // 3. 标识符（变量引用）
    if (node.type === 'Identifier') {
        const binding = scope.getBinding(node.name);
        
        if (binding) {
            // 3.1 变量定义 (const a = "val")
            if (binding.path.isVariableDeclarator() && binding.path.node.init) {
                if (!binding.path._visited) {
                    binding.path._visited = true;
                    const val = evaluateExpression(binding.path.node.init, binding.scope, localBindings);
                    binding.path._visited = false;
                    if (val !== null && (typeof val !== 'string' || !val.includes('${'))) return val;
                }
            }
            // 3.2 导入
            if (binding.kind === 'module') {
                return `\${Import:${node.name}}`;
            }
        } else {
             return `\${Global:${node.name}}`;
        }
        return `\${${node.name}}`;
    }

    // 4. 二元表达式
    if (node.type === 'BinaryExpression') {
        const left = evaluateExpression(node.left, scope, localBindings);
        const right = evaluateExpression(node.right, scope, localBindings);
        
        if (node.operator === '+') {
            const lVal = left !== null ? left : '';
            const rVal = right !== null ? right : '';
            // 只要任何一边非空，就尝试拼接。即使有一边是空字符串（解析失败），也返回部分结果
            // 例如 "http://api.com/" + unknown_var -> "http://api.com/"
            if (lVal === '' && rVal === '') return '${...}';
            return lVal + rVal;
        }
        // 数值运算
        if (typeof left === 'number' && typeof right === 'number') {
            if (node.operator === '-') return left - right;
            if (node.operator === '*') return left * right;
            if (node.operator === '/') return left / right;
            if (node.operator === '%') return left % right;
        }
    }
    
    // 5. 条件表达式 (Ternary)
    if (node.type === 'ConditionalExpression') {
        const test = evaluateExpression(node.test, scope, localBindings);
        if (test === true) return evaluateExpression(node.consequent, scope, localBindings);
        if (test === false) return evaluateExpression(node.alternate, scope, localBindings);
        return evaluateExpression(node.consequent, scope, localBindings);
    }

    // 6. 数组表达式 (用于 join)
    if (node.type === 'ArrayExpression') {
        return node.elements.map(e => evaluateExpression(e, scope, localBindings));
    }

    // 7. 成员表达式 (config.api_base 或 arr.join)
    if (node.type === 'MemberExpression') {
        let object = null;
        if (node.object.type === 'Identifier') {
            object = evaluateExpression(node.object, scope, localBindings);
            if (!object || typeof object === 'string') {
                const binding = scope.getBinding(node.object.name);
                if (binding && binding.path.isVariableDeclarator() && binding.path.node.init && binding.path.node.init.type === 'ObjectExpression') {
                    const propName = node.property.name;
                    const prop = binding.path.node.init.properties.find(p => p.key.name === propName || p.key.value === propName);
                    if (prop) {
                        return evaluateExpression(prop.value, binding.scope, localBindings);
                    }
                }
            }
        }
        
        try {
            const getName = (n) => {
                if (n.type === 'Identifier') return n.name;
                if (n.type === 'MemberExpression') return `${getName(n.object)}.${n.property.name}`;
                return '...';
            };
            return `\${${getName(node)}}`;
        } catch (e) {
            return '${MemberExpression}';
        }
    }

    // 8. 函数调用
    if (node.type === 'CallExpression') {
        // 8.1 .join()
        if (node.callee.type === 'MemberExpression' && node.callee.property.name === 'join') {
             const object = evaluateExpression(node.callee.object, scope, localBindings);
             if (Array.isArray(object)) {
                 const separatorArg = node.arguments[0];
                 const separator = separatorArg ? evaluateExpression(separatorArg, scope, localBindings) : ',';
                 const validElements = object.filter(e => e !== null);
                 return validElements.join(separator !== null ? separator : ',');
             }
        }
        
        // 8.2 简单函数内联
        if (node.callee.type === 'Identifier') {
             const binding = scope.getBinding(node.callee.name);
             if (binding && (binding.path.isVariableDeclarator() || binding.path.isFunctionDeclaration())) {
                  const init = binding.path.node.init || binding.path.node;
                  if (init && (init.type === 'ArrowFunctionExpression' || init.type === 'FunctionExpression')) {
                      const params = init.params.map(p => p.name);
                      const args = node.arguments.map(a => evaluateExpression(a, scope, localBindings));
                      
                      const newBindings = { ...localBindings };
                      params.forEach((p, idx) => {
                          if (idx < args.length) newBindings[p] = args[idx];
                      });
                      
                      if (init.body.type !== 'BlockStatement') {
                          return evaluateExpression(init.body, binding.scope, newBindings);
                      } else {
                          const returnStmt = init.body.body.find(s => s.type === 'ReturnStatement');
                          if (returnStmt) {
                              return evaluateExpression(returnStmt.argument, binding.scope, newBindings);
                          }
                      }
                  }
             }
             return `\${Call:${node.callee.name}}`;
        }
        return '${CallExpression}';
    }

    return null;
}

// 辅助函数：提取对象参数 Key
function extractParams(node, scope) {
    let params = [];
    if (!node) return params;

    if (node.type === 'ObjectExpression') {
        node.properties.forEach(prop => {
            if (prop.type === 'ObjectProperty') {
                if (prop.key.type === 'Identifier') {
                    params.push(prop.key.name);
                } else if (prop.key.type === 'StringLiteral') {
                    params.push(prop.key.value);
                }
            }
        });
    } else if (node.type === 'CallExpression' && 
             node.callee.type === 'MemberExpression' &&
             node.callee.object.name === 'JSON' && 
             node.callee.property.name === 'stringify') {
        if (node.arguments.length > 0) {
            return extractParams(node.arguments[0], scope);
        }
    } else if (node.type === 'Identifier') {
         const binding = scope.getBinding(node.name);
         if (binding) {
             if (binding.path.isVariableDeclarator()) {
                 const init = binding.path.node.init;
                 if (init) {
                     if (!binding.path._visited_params) {
                         binding.path._visited_params = true;
                         params = params.concat(extractParams(init, binding.scope));
                         binding.path._visited_params = false;
                     }
                 }
                 if (init && init.type === 'NewExpression' && 
                    (init.callee.name === 'FormData' || init.callee.name === 'URLSearchParams')) {
                     if (binding.referencePaths) {
                         binding.referencePaths.forEach(refPath => {
                             if (refPath.parentPath.isMemberExpression() && refPath.parentPath.node.property.name === 'append') {
                                 const callExpr = refPath.parentPath.parentPath;
                                 if (callExpr.isCallExpression()) {
                                     const args = callExpr.node.arguments;
                                     if (args.length > 0 && args[0].type === 'StringLiteral') {
                                         params.push(args[0].value);
                                     }
                                 }
                             }
                         });
                     }
                 }
             }
         }
    } else if (node.type === 'NewExpression' && node.callee.name === 'URLSearchParams') {
        if (node.arguments.length > 0) {
            return extractParams(node.arguments[0], scope);
        }
    }

    return params;
}

function tagParams(params, source) {
    const arr = Array.isArray(params) ? params : [];
    return arr.filter(n => typeof n === 'string' && n).map(n => ({ name: n, source }));
}

function analyzeFile(filePath) {
    let code = '';
    try {
        code = fs.readFileSync(filePath, 'utf-8');
    } catch (e) {
        return { error: `Failed to read file: ${e.message}`, file: filePath };
    }

    try {
        const ast = parser.parse(code, {
            sourceType: 'module',
            plugins: ['jsx', 'typescript', 'classProperties', 'decorators-legacy', 'dynamicImport']
        });

        const apis = [];
        const urls = [];
        const dynamic_imports = [];

        traverse(ast, {
            CallExpression(path) {
                const { callee, arguments: args } = path.node;
                
                // 1. fetch
                if (callee.name === 'fetch') {
                    const urlArg = args[0];
                    let url = 'UNKNOWN';
                    let method = 'GET';
                    if (urlArg && urlArg.type === 'NewExpression' && urlArg.callee && urlArg.callee.name === 'URL') {
                        const u0 = urlArg.arguments[0] ? evaluateExpression(urlArg.arguments[0], path.scope) : '';
                        const u1 = urlArg.arguments[1] ? evaluateExpression(urlArg.arguments[1], path.scope) : '';
                        const combined = (u1 || '') + (u0 || '');
                        if (combined) url = combined;
                    } else {
                        const evaluatedUrl = evaluateExpression(urlArg, path.scope);
                        if (evaluatedUrl) url = evaluatedUrl;
                    }

                    let params = [];
                    let param_sources = [];
                    if (args[1] && args[1].type === 'ObjectExpression') {
                        const methodProp = args[1].properties.find(p => p.key.name === 'method');
                        if (methodProp && methodProp.value.type === 'StringLiteral') method = methodProp.value.value;
                        const bodyProp = args[1].properties.find(p => p.key.name === 'body');
                        if (bodyProp) {
                            params = extractParams(bodyProp.value, path.scope);
                            param_sources = param_sources.concat(tagParams(params, 'body'));
                        }
                    }
                    apis.push({ tool: 'fetch', url, method, params, param_sources, loc: path.node.loc.start.line, context: getContextCode(code, path.node.loc), args: args.length });
                }
                
                // 2. axios
                if (callee.type === 'MemberExpression' && callee.object.name === 'axios') {
                    const method = callee.property.name;
                    const urlArg = args[0];
                    let url = 'UNKNOWN';
                    if (urlArg && urlArg.type === 'NewExpression' && urlArg.callee && urlArg.callee.name === 'URL') {
                        const u0 = urlArg.arguments[0] ? evaluateExpression(urlArg.arguments[0], path.scope) : '';
                        const u1 = urlArg.arguments[1] ? evaluateExpression(urlArg.arguments[1], path.scope) : '';
                        const combined = (u1 || '') + (u0 || '');
                        if (combined) url = combined;
                    } else {
                        const evaluatedUrl = evaluateExpression(urlArg, path.scope);
                        if (evaluatedUrl) url = evaluatedUrl;
                    }

                    let params = [];
                    let param_sources = [];
                    if (['post', 'put', 'patch'].includes(method.toLowerCase()) && args[1]) {
                        params = extractParams(args[1], path.scope);
                        param_sources = param_sources.concat(tagParams(params, 'data'));
                    } else if (['get', 'delete'].includes(method.toLowerCase()) && args[1]) {
                        if (args[1].type === 'ObjectExpression') {
                            const paramsProp = args[1].properties.find(p => p.key.name === 'params');
                            if (paramsProp) {
                                const p = extractParams(paramsProp.value, path.scope);
                                params = p;
                                param_sources = param_sources.concat(tagParams(p, 'params'));
                            }
                        }
                    }
                    apis.push({ tool: 'axios', method, url, params, param_sources, loc: path.node.loc.start.line, context: getContextCode(code, path.node.loc), args: args.length });
                }
                
                // 3. $.ajax
                if (callee.type === 'MemberExpression' && (callee.object.name === '$' || callee.object.name === 'jQuery') && callee.property.name === 'ajax') {
                    let url = 'UNKNOWN';
                    let method = 'GET';
                    let params = [];
                    let param_sources = [];
                    if (args[0] && args[0].type === 'ObjectExpression') {
                        const urlProp = args[0].properties.find(p => p.key.name === 'url');
                        const methodProp = args[0].properties.find(p => p.key.name === 'type' || p.key.name === 'method');
                        if (urlProp) {
                            const evalUrl = evaluateExpression(urlProp.value, path.scope);
                            if (evalUrl) url = evalUrl;
                        }
                        if (methodProp && methodProp.value.type === 'StringLiteral') method = methodProp.value.value;
                        const dataProp = args[0].properties.find(p => p.key.name === 'data');
                        if (dataProp) {
                            params = extractParams(dataProp.value, path.scope);
                            param_sources = param_sources.concat(tagParams(params, 'data'));
                        }
                    }
                    apis.push({ tool: 'jquery', method, url, params, param_sources, loc: path.node.loc.start.line, context: getContextCode(code, path.node.loc) });
                }
                
                // 4. axios(config)
                if (callee.type === 'Identifier' && callee.name === 'axios') {
                    let url = 'UNKNOWN';
                    let method = 'GET';
                    let params = [];
                    let param_sources = [];
                    if (args[0] && args[0].type === 'ObjectExpression') {
                        const urlProp = args[0].properties.find(p => p.key.name === 'url');
                        if (urlProp) {
                            const evalUrl = evaluateExpression(urlProp.value, path.scope);
                            if (evalUrl) url = evalUrl;
                        }
                        const methodProp = args[0].properties.find(p => p.key.name === 'method');
                        if (methodProp && methodProp.value.type === 'StringLiteral') method = methodProp.value.value;
                        const dataProp = args[0].properties.find(p => p.key.name === 'data');
                        if (dataProp) {
                            const p = extractParams(dataProp.value, path.scope);
                            params = params.concat(p);
                            param_sources = param_sources.concat(tagParams(p, 'data'));
                        }
                        const paramsProp = args[0].properties.find(p => p.key.name === 'params');
                        if (paramsProp) {
                            const p2 = extractParams(paramsProp.value, path.scope);
                            params = params.concat(p2);
                            param_sources = param_sources.concat(tagParams(p2, 'params'));
                        }
                    }
                    apis.push({ tool: 'axios', method, url, params, param_sources, loc: path.node.loc.start.line, context: getContextCode(code, path.node.loc), args: args.length });
                }
                
                // 5. xhr
                if (callee.type === 'MemberExpression' && callee.property.name === 'open') {
                    if (args.length >= 2) {
                        let method = 'UNKNOWN';
                        let url = 'UNKNOWN';
                        if (args[0].type === 'StringLiteral') method = args[0].value;
                        const evalUrl = evaluateExpression(args[1], path.scope);
                        if (evalUrl) url = evalUrl;
                        apis.push({ tool: 'xhr', method, url, params: [], param_sources: [], loc: path.node.loc.start.line, context: getContextCode(code, path.node.loc) });
                    }
                }

                // 6. Vue Resource
                if (callee.type === 'MemberExpression' && callee.object.type === 'MemberExpression' && callee.object.property.name === '$http') {
                    const method = callee.property.name;
                    const urlArg = args[0];
                    let url = 'UNKNOWN';
                    const evaluatedUrl = evaluateExpression(urlArg, path.scope);
                    if (evaluatedUrl) url = evaluatedUrl;
                    let params = [];
                    let param_sources = [];
                    if (args[1]) {
                        params = extractParams(args[1], path.scope);
                        param_sources = param_sources.concat(tagParams(params, 'data'));
                    }
                    apis.push({ tool: 'vue-resource', method, url, params, param_sources, loc: path.node.loc.start.line, context: getContextCode(code, path.node.loc) });
                }

                // 7. Angular
                if (callee.type === 'MemberExpression' && callee.object.type === 'MemberExpression' && callee.object.property.name === 'http') {
                    const method = callee.property.name;
                    const urlArg = args[0];
                    let url = 'UNKNOWN';
                    const evaluatedUrl = evaluateExpression(urlArg, path.scope);
                    if (evaluatedUrl) url = evaluatedUrl;
                    let params = [];
                    let param_sources = [];
                    if (['post', 'put', 'patch'].includes(method.toLowerCase()) && args[1]) {
                        params = extractParams(args[1], path.scope);
                        param_sources = param_sources.concat(tagParams(params, 'data'));
                    } else if (['get', 'delete'].includes(method.toLowerCase()) && args[1]) {
                        if (args[1].type === 'ObjectExpression') {
                            const paramsProp = args[1].properties.find(p => p.key.name === 'params');
                            if (paramsProp) {
                                const p = extractParams(paramsProp.value, path.scope);
                                params = p;
                                param_sources = param_sources.concat(tagParams(p, 'params'));
                            }
                        }
                    }
                    apis.push({ tool: 'angular-http', method, url, params, param_sources, loc: path.node.loc.start.line, context: getContextCode(code, path.node.loc) });
                }
                
                // 8. Mini Programs
                if (callee.type === 'MemberExpression' && ['uni', 'wx', 'my', 'tt', 'swan'].includes(callee.object.name) && callee.property.name === 'request') {
                    let url = 'UNKNOWN';
                    let method = 'GET';
                    let params = [];
                    let param_sources = [];
                    if (args[0] && args[0].type === 'ObjectExpression') {
                        const urlProp = args[0].properties.find(p => p.key.name === 'url');
                        if (urlProp) {
                            const evalUrl = evaluateExpression(urlProp.value, path.scope);
                            if (evalUrl) url = evalUrl;
                        }
                        const methodProp = args[0].properties.find(p => p.key.name === 'method');
                        if (methodProp && methodProp.value.type === 'StringLiteral') method = methodProp.value.value;
                        const dataProp = args[0].properties.find(p => p.key.name === 'data');
                        if (dataProp) {
                            params = extractParams(dataProp.value, path.scope);
                            param_sources = param_sources.concat(tagParams(params, 'data'));
                        }
                    }
                    apis.push({ tool: 'mini-program', method, url, params, param_sources, loc: path.node.loc.start.line, context: getContextCode(code, path.node.loc) });
                }

                // 9. Heuristic
                if (callee.type === 'MemberExpression' && ['get', 'post', 'put', 'delete', 'patch', 'request'].includes(callee.property.name)) {
                    if (args.length > 0) {
                        const arg0 = args[0];
                        let looksLikeUrl = false;
                        let url = 'UNKNOWN';
                        const evalUrl = evaluateExpression(arg0, path.scope);
                        if (evalUrl && typeof evalUrl === 'string') {
                            if (evalUrl.includes('/') && (evalUrl.startsWith('/') || evalUrl.startsWith('http') || evalUrl.includes('api'))) {
                                looksLikeUrl = true;
                                url = evalUrl;
                            }
                        }
                        const isAlreadyCaught = callee.object.name === 'axios' || callee.object.name === 'http' || callee.object.property?.name === '$http';
                        if (looksLikeUrl && !isAlreadyCaught) {
                            let method = callee.property.name.toUpperCase();
                            if (method === 'REQUEST') method = 'UNKNOWN';
                            let params = [];
                            let param_sources = [];
                            if (['POST', 'PUT', 'PATCH'].includes(method) && args[1]) {
                                params = extractParams(args[1], path.scope);
                                param_sources = param_sources.concat(tagParams(params, 'data'));
                            }
                            apis.push({ tool: 'heuristic', method, url, params, param_sources, loc: path.node.loc.start.line, context: getContextCode(code, path.node.loc) });
                        }
                    }
                }
                
                // 10. navigator.sendBeacon
                if (callee.type === 'MemberExpression' && callee.property.name === 'sendBeacon' && callee.object.name === 'navigator') {
                    const urlArg = args[0];
                    let url = 'UNKNOWN';
                    const evalUrl = evaluateExpression(urlArg, path.scope);
                    if (evalUrl) url = evalUrl;
                    
                    let params = [];
                    let param_sources = [];
                    if (args[1]) {
                        params = extractParams(args[1], path.scope);
                        param_sources = param_sources.concat(tagParams(params, 'data'));
                    }
                    apis.push({ tool: 'sendBeacon', method: 'POST', url, params, param_sources, loc: path.node.loc.start.line, context: getContextCode(code, path.node.loc) });
                }

                // 11. Generic Config Object Request (e.g. request({ url: '...', method: '...' }))
                if (args.length > 0 && args[0].type === 'ObjectExpression') {
                    const urlProp = args[0].properties.find(p => p.key && p.key.name === 'url');
                    if (urlProp) {
                        const evalUrl = evaluateExpression(urlProp.value, path.scope);
                        if (evalUrl && typeof evalUrl === 'string' && (evalUrl.startsWith('/') || evalUrl.startsWith('http') || evalUrl.includes('/'))) {
                            let url = evalUrl;
                            let method = 'GET'; // Default
                            let params = [];
                            let param_sources = [];
                            
                            const methodProp = args[0].properties.find(p => p.key && p.key.name === 'method');
                            if (methodProp && methodProp.value.type === 'StringLiteral') {
                                method = methodProp.value.value;
                            }
                            
                            const dataProp = args[0].properties.find(p => p.key && p.key.name === 'data');
                            if (dataProp) {
                                const p = extractParams(dataProp.value, path.scope);
                                params = params.concat(p);
                                param_sources = param_sources.concat(tagParams(p, 'data'));
                            }
                            
                            const paramsProp = args[0].properties.find(p => p.key && p.key.name === 'params');
                            if (paramsProp) {
                                const p2 = extractParams(paramsProp.value, path.scope);
                                params = params.concat(p2);
                                param_sources = param_sources.concat(tagParams(p2, 'params'));
                            }
                            
                            let isDuplicate = false;
                            if (callee.type === 'Identifier' && callee.name === 'axios') isDuplicate = true;
                            if (callee.type === 'MemberExpression' && (callee.object.name === '$' || callee.object.name === 'jQuery') && callee.property.name === 'ajax') isDuplicate = true;
                            
                            if (!isDuplicate) {
                                apis.push({
                                    tool: 'generic-request',
                                    method: method,
                                    url: url,
                                    params: params,
                                    param_sources: param_sources,
                                    loc: path.node.loc.start.line,
                                    context: getContextCode(code, path.node.loc)
                                });
                            }
                        }
                    }
                }
                
                if (callee.type === 'Import') {
                    if (args.length > 0) {
                        const evalPath = evaluateExpression(args[0], path.scope);
                        if (evalPath && typeof evalPath === 'string') {
                            dynamic_imports.push({ value: evalPath, loc: path.node.loc.start.line, context: getContextCode(code, path.node.loc), type: 'import_call' });
                        } else {
                            dynamic_imports.push({ value: '${...}', loc: path.node.loc.start.line, context: getContextCode(code, path.node.loc), type: 'import_call' });
                        }
                    }
                }
            },

            StringLiteral(path) {
                const val = path.node.value;
                // 去除可能存在的反引号或引号包裹（针对特定模板语法误报），并去除两端空白字符
                const cleanVal = val.replace(/^[`"']+|[`"']$/g, '').trim();
                
                if (cleanVal.includes('/')) {
                    if ((cleanVal.startsWith('http') || cleanVal.startsWith('/') || cleanVal.includes('/api/') || cleanVal.includes('/v1/') || cleanVal.endsWith('/'))) {
                        // 移除对空格的严格检查，允许URL中包含编码后的空格或其他合法字符，但在长度检查时依然保留
                        // 但对于普通提取，如果包含换行符通常是不合法的URL
                        if (cleanVal.length > 2 && !cleanVal.includes('\n')) {
                            urls.push({ value: cleanVal, loc: path.node.loc.start.line, context: getContextCode(code, path.node.loc), type: 'string_literal' });
                        }
                    }
                }
            },

            TemplateLiteral(path) {
                const raw = path.node.quasis.map(q => q.value.raw).join('${...}');
                if (raw.includes('/') && (raw.startsWith('http') || raw.startsWith('/') || raw.includes('/api/'))) {
                    const evaluated = evaluateExpression(path.node, path.scope);
                    if (evaluated) {
                        urls.push({ value: evaluated, loc: path.node.loc.start.line, context: getContextCode(code, path.node.loc), type: 'template_literal' });
                    }
                }
            },
            
            ObjectProperty(path) {
                const { key, value } = path.node;
                const evaluated = evaluateExpression(value, path.scope);
                if (evaluated && typeof evaluated === 'string' && evaluated.includes('/')) {
                    if (evaluated.startsWith('http') || evaluated.startsWith('/') || evaluated.includes('${...}') || evaluated.endsWith('/')) {
                        urls.push({ value: evaluated, loc: path.node.loc.start.line, context: getContextCode(code, path.node.loc), type: 'property_assignment' });
                    }
                }
            }
        });

        return { apis: apis, urls: urls, dynamic_imports: dynamic_imports, file: filePath };

    } catch (e) {
        return { error: e.message, stack: e.stack, file: filePath };
    }
}

// 主入口
const arg = process.argv[2];

if (!arg) {
    console.error(JSON.stringify({ error: 'No file path provided' }));
    process.exit(1);
}

if (arg === '--batch') {
    const batchFile = process.argv[3];
    if (!batchFile) {
        console.error(JSON.stringify({ error: 'No batch file provided' }));
        process.exit(1);
    }
    
    try {
        const filePaths = JSON.parse(fs.readFileSync(batchFile, 'utf-8'));
        const results = [];
        for (const file of filePaths) {
            results.push(analyzeFile(file));
        }
        console.log(JSON.stringify(results));
    } catch (e) {
        console.error(JSON.stringify({ error: `Batch processing failed: ${e.message}` }));
        process.exit(1);
    }
} else {
    // 兼容旧模式
    const result = analyzeFile(arg);
    console.log(JSON.stringify(result, null, 2));
}
