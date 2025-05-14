// frontend/my-react-app/src/components/pages/Portfolio/CodeEditor.js
import React, { useEffect, useRef, useState } from 'react';
import { Editor } from '@monaco-editor/react';

const CodeEditor = ({ value, language, theme, onChange, onError }) => {
  const editorRef = useRef(null);
  const [editorHeight, setEditorHeight] = useState('650px'); // Increased default height
  const containerRef = useRef(null);

  // Resize handler to make editor responsive
  useEffect(() => {
    const handleResize = () => {
      if (containerRef.current) {
        // Calculate available height (viewport height minus offset for other UI elements)
        const viewportHeight = window.innerHeight;
        const newHeight = Math.max(500, viewportHeight * 0.6); // At least 500px, up to 60% of viewport
        setEditorHeight(`${newHeight}px`);
      }
    };

    // Initial sizing
    handleResize();
    
    // Add resize event listener
    window.addEventListener('resize', handleResize);
    
    return () => {
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  const handleEditorDidMount = (editor, monaco) => {
    editorRef.current = editor;
    
    // Apply custom editor settings
    editor.updateOptions({
      lineHeight: 20,
      fontFamily: "'Fira Code', 'Consolas', monospace",
      fontLigatures: true,
      cursorSmoothCaretAnimation: "on",
    });
    
    // Set up validation for JavaScript files
    if (language === 'javascript' || language === 'jsx') {
      // Use Monaco's model markers to check for errors
      const checkErrors = () => {
        const markers = monaco.editor.getModelMarkers({ owner: 'javascript' });
        if (markers.length > 0) {
          // Get the most critical error
          const errorMarker = markers.sort((a, b) => b.severity - a.severity)[0];
          const errorMessage = `${errorMarker.message} (Line ${errorMarker.startLineNumber})`;
          if (onError) onError(errorMessage);
        } else {
          // Clear previous errors
          if (onError) onError(null);
        }
      };
      
      // Check for errors after a brief delay when content changes
      editor.onDidChangeModelContent(() => {
        setTimeout(checkErrors, 1000);
      });
      
      // Check errors on initial load
      setTimeout(checkErrors, 1500);
    }
  };

  useEffect(() => {
    // Make sure the editor has been mounted
    if (!editorRef.current) return;
    
    // Set the value when it changes externally
    if (editorRef.current.getValue() !== value) {
      editorRef.current.setValue(value);
    }
  }, [value]);

  return (
    <div ref={containerRef} className="portfolio-code-editor-wrapper">
      <Editor
        height={editorHeight}
        width="100%"
        language={language}
        theme={theme || "vs-dark"}
        value={value}
        onMount={handleEditorDidMount}
        onChange={(newValue) => onChange(newValue)}
        options={{
          minimap: { enabled: true },
          lineNumbers: 'on',
          scrollBeyondLastLine: false,
          fontSize: 14,
          autoIndent: 'full',
          formatOnPaste: true,
          formatOnType: true,
          wordWrap: 'on',
          scrollbar: {
            vertical: 'visible',
            horizontal: 'visible',
            useShadows: true,
            verticalHasArrows: true,
            horizontalHasArrows: true
          },
          suggest: {
            showIcons: true,
            showFunctions: true,
            showConstructors: true,
            showVariables: true,
            showClasses: true,
            showStructs: true,
            showInterfaces: true,
            showModules: true
          }
        }}
      />
    </div>
  );
};

export default CodeEditor;
