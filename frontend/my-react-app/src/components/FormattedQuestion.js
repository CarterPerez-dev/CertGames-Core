import React from 'react';
import hljs from 'highlight.js/lib/core';
import 'highlight.js/styles/atom-one-dark.css';  // Choose a theme that matches your preferences

// Import and register language modules
import javascript from 'highlight.js/lib/languages/javascript';
import python from 'highlight.js/lib/languages/python';
import bash from 'highlight.js/lib/languages/bash';
import yaml from 'highlight.js/lib/languages/yaml';
import json from 'highlight.js/lib/languages/json';
import sql from 'highlight.js/lib/languages/sql';
// Note: For HCL, we'll use a more generic approach since it doesn't have direct support

// Register languages
hljs.registerLanguage('javascript', javascript);
hljs.registerLanguage('python', python);
hljs.registerLanguage('bash', bash);
hljs.registerLanguage('yaml', yaml);
hljs.registerLanguage('json', json);
hljs.registerLanguage('sql', sql);

const FormattedQuestion = ({ questionText }) => {
  // Process the question text to handle formatting
  const processedContent = React.useMemo(() => {
    // Return empty array if no question text
    if (!questionText) return [];
    
    // Split the content by code blocks first
    const parts = [];
    let lastIndex = 0;
    
    // Find all code blocks (both triple backtick and single backtick)
    const codeBlockRegex = /```(\w*)\n([\s\S]*?)```|`([^`]+)`/g;
    let match;
    
    while ((match = codeBlockRegex.exec(questionText)) !== null) {
      // Add text before the code block
      if (match.index > lastIndex) {
        parts.push({
          type: 'text',
          content: questionText.substring(lastIndex, match.index)
        });
      }
      
      // Check if this is a triple backtick code block or inline code
      if (match[2]) {
        // Triple backtick code block
        parts.push({
          type: 'code-block',
          language: match[1] || 'plaintext',
          content: match[2]
        });
      } else {
        // Inline code
        parts.push({
          type: 'inline-code',
          content: match[3]
        });
      }
      
      lastIndex = match.index + match[0].length;
    }
    
    // Add any remaining text
    if (lastIndex < questionText.length) {
      parts.push({
        type: 'text',
        content: questionText.substring(lastIndex)
      });
    }
    
    // Process tables in text parts
    const processedParts = parts.map(part => {
      if (part.type !== 'text') return part;
      
      // Check for table patterns
      if (part.content.includes('|') && part.content.includes('\n') &&
          part.content.match(/\|[\s-]+\|/)) {
        return {
          type: 'table',
          content: part.content
        };
      }
      
      // Check for ASCII diagrams (lines with lots of special chars like -│┌┐└┘)
      if (part.content.match(/[│├┤┌┐└┘┬┴┼─|/\\+*=><^v]/g) && 
          part.content.split('\n').some(line => 
            (line.match(/[│├┤┌┐└┘┬┴┼─|/\\+*=><^v]/g) || []).length > 5)) {
        return {
          type: 'ascii-diagram',
          content: part.content
        };
      }
      
      return part;
    });
    
    return processedParts;
  }, [questionText]);

  // Function to highlight code using highlight.js
  const highlightCode = (code, language) => {
    try {
      // For HCL code, we can try using an alternative language for highlighting
      if (language === 'hcl') {
        // Try to use yaml as it has somewhat similar syntax highlighting
        language = 'yaml';
      }
      
      // If language is specified and supported
      if (language && hljs.getLanguage(language)) {
        return hljs.highlight(code, { language }).value;
      }
      // Auto-detect language
      return hljs.highlightAuto(code).value;
    } catch (error) {
      console.warn('Failed to highlight code:', error);
      return code;
    }
  };

  // Function to format tables
  const formatTable = (tableText) => {
    const lines = tableText.split('\n').filter(line => line.trim());
    if (lines.length < 2) return tableText;

    // Check if the second line contains a separator row (e.g., |------|------|)
    const isMarkdownTable = lines[1].match(/\|[-:\s]+\|/);
    
    if (!isMarkdownTable) {
      // Treat as pre-formatted text if not a markdown table
      return (
        <pre className="formatted-pre">{tableText}</pre>
      );
    }

    // Process markdown table
    const headerRow = lines[0];
    const headerCells = headerRow.split('|')
      .filter(cell => cell.trim())
      .map(cell => cell.trim());
    
    // Skip the separator row and process data rows
    const dataRows = lines.slice(2).map(row => {
      return row.split('|')
        .filter(cell => cell.trim())
        .map(cell => cell.trim());
    });
    
    return (
      <table className="formatted-table">
        <thead>
          <tr>
            {headerCells.map((cell, i) => (
              <th key={i}>{cell}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {dataRows.map((row, i) => (
            <tr key={i}>
              {row.map((cell, j) => (
                <td key={j}>{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    );
  };

  // Early return after hooks are called
  if (!questionText) return null;

  // Render the content based on the processed parts
  return (
    <div className="formatted-question">
      {processedContent.map((part, index) => {
        switch (part.type) {
          case 'code-block':
            return (
              <pre key={index} className={`hljs language-${part.language} formatted-code-block`}>
                <code 
                  dangerouslySetInnerHTML={{ 
                    __html: highlightCode(part.content, part.language) 
                  }}
                  className="wrap-long-lines" // Add a class for line wrapping
                />
              </pre>
            );
          
          case 'inline-code':
            return (
              <code key={index} className="formatted-inline-code">
                {part.content}
              </code>
            );
          
          case 'table':
            return (
              <div key={index} className="formatted-table-container">
                {formatTable(part.content)}
              </div>
            );
          
          case 'ascii-diagram':
            return (
              <pre key={index} className="formatted-ascii-diagram">
                {part.content}
              </pre>
            );
          
          default:
            // Handle regular text (preserving newlines and formatting)
            return (
              <div key={index} className="formatted-text">
                {part.content.split('\n').map((line, i) => (
                  <React.Fragment key={i}>
                    {line}
                    {i < part.content.split('\n').length - 1 && <br />}
                  </React.Fragment>
                ))}
              </div>
            );
        }
      })}
    </div>
  );
};

export default FormattedQuestion;
