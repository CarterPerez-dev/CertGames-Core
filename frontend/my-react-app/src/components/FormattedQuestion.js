import React from 'react';
import Prism from 'prismjs';
import 'prismjs/themes/prism-tomorrow.css';
import 'prismjs/components/prism-python';
import 'prismjs/components/prism-javascript';
import 'prismjs/components/prism-bash';
import 'prismjs/components/prism-yaml';
import 'prismjs/components/prism-json';
import 'prismjs/components/prism-sql';
import 'prismjs/components/prism-hcl';



const FormattedQuestion = ({ questionText }) => {
  if (!questionText) return null;

  // Process the question text to handle formatting
  const processedContent = React.useMemo(() => {
    // Split the content by code blocks first
    const parts = [];
    let lastIndex = 0;
    let inCodeBlock = false;
    let currentLanguage = '';
    
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

  // Function to highlight code using Prism
  const highlightCode = (code, language) => {
    try {
      if (Prism.languages[language]) {
        return Prism.highlight(code, Prism.languages[language], language);
      }
      return Prism.highlight(code, Prism.languages.javascript, 'javascript');
    } catch (error) {
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

  // Render the content based on the processed parts
  return (
    <div className="formatted-question">
      {processedContent.map((part, index) => {
        switch (part.type) {
          case 'code-block':
            return (
              <pre key={index} className={`language-${part.language} formatted-code-block`}>
                <code dangerouslySetInnerHTML={{ 
                  __html: highlightCode(part.content, part.language) 
                }} />
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
