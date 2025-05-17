import React, { useEffect, useRef, useState } from 'react';
import { Editor } from '@monaco-editor/react';

const CodeEditor = ({ value, language, theme, onChange, onError }) => {
  const editorRef = useRef(null);
  const [editorHeight, setEditorHeight] = useState('650px');
  const containerRef = useRef(null);
  const [initialValue, setInitialValue] = useState('');

  // Set initial value when component mounts to prevent value changes triggering errors
  useEffect(() => {
    setInitialValue(value || '');
  }, []);

  useEffect(() => {
    let resizeTimeout = null;

    const handleResize = () => {
      if (resizeTimeout) {
        clearTimeout(resizeTimeout);
      }

      resizeTimeout = setTimeout(() => {
        const viewportHeight = window.innerHeight;
        const newHeight = Math.max(500, viewportHeight * 0.6);
        setEditorHeight(`${newHeight}px`);
      }, 100);
    };

    handleResize();
    window.addEventListener('resize', handleResize, { passive: true });

    return () => {
      window.removeEventListener('resize', handleResize);
      if (resizeTimeout) {
        clearTimeout(resizeTimeout);
      }
    };
  }, []);

  const handleEditorDidMount = (editor, monaco) => {
    editorRef.current = editor;

    editor.updateOptions({
      lineHeight: 20,
      fontFamily: "'Fira Code', 'Consolas', monospace",
      fontLigatures: true,
      cursorSmoothCaretAnimation: "on",
    });

    // Set the editor content safely after mount
    if (value) {
      // Use model API instead of setValue to prevent errors
      const model = editor.getModel();
      if (model) {
        model.setValue(value);
      }
    }

    if (language === 'javascript' || language === 'jsx') {
      const checkErrors = () => {
        const model = editor.getModel();
        if (!model) return;
        const markers = monaco.editor.getModelMarkers({ resource: model.uri });
        if (markers.length > 0) {
          const errorMarker = markers.sort((a, b) => b.severity - a.severity)[0];
          const errorMessage = `${errorMarker.message} (Line ${errorMarker.startLineNumber})`;
          if (onError) onError(errorMessage);
        } else {
          if (onError) onError(null);
        }
      };

      let errorCheckTimeout = null;
      editor.onDidChangeModelContent(() => {
        if (errorCheckTimeout) clearTimeout(errorCheckTimeout);
        errorCheckTimeout = setTimeout(checkErrors, 1000);
      });
      
      // Check errors on initial load if there's initial content
      if (value) {
         setTimeout(checkErrors, 1500);
      }
    }
  };
  
  // Safely handle content changes
  const handleEditorChange = (newValue) => {
    if (onChange && typeof newValue === 'string') {
      onChange(newValue);
    }
  };

  return (
    <div ref={containerRef} className="portfolio-code-editor-wrapper" style={{ width: '100%' }}>
      <Editor
        height={editorHeight}
        width="100%"
        language={language || 'javascript'}
        theme={theme || "vs-dark"}
        defaultValue={initialValue}
        onMount={handleEditorDidMount}
        onChange={handleEditorChange}
        options={{
          minimap: { enabled: true },
          lineNumbers: 'on',
          scrollBeyondLastLine: false,
          fontSize: 14,
          autoIndent: 'full',
          formatOnPaste: true,
          formatOnType: true,
          wordWrap: 'on',
          automaticLayout: true,
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
