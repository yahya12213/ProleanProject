import React from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { FileText, Eye, Trash2, Download } from 'lucide-react';

interface Document {
  id: string;
  document_name: string;
  document_url: string;
  uploaded_at: string;
  description?: string;
}

interface DocumentListProps {
  title: string;
  documents: Document[];
  onDelete: (documentId: string) => void;
  emptyMessage?: string;
}

const DocumentList: React.FC<DocumentListProps> = ({ 
  title, 
  documents, 
  onDelete, 
  emptyMessage = "Aucun document" 
}) => {
  const downloadDocument = (url: string, name: string) => {
    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const viewDocument = (doc: Document) => {
    const url = doc.document_url.includes('public/employee-documents')
      ? doc.document_url
      : `/storage/employee-documents/${doc.document_url.split('/').pop()}`;
    window.open(url, '_blank');
  };

  if (documents.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium text-muted-foreground">
            {title}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">{emptyMessage}</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium flex items-center justify-between">
          {title}
          <Badge variant="secondary">{documents.length}</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {documents.map((doc) => (
          <div key={doc.id} className="flex items-center justify-between p-3 border rounded-lg bg-background">
            <div className="flex items-center space-x-3 flex-1 min-w-0">
              <FileText className="h-4 w-4 text-muted-foreground flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{doc.document_name}</p>
                <p className="text-xs text-muted-foreground">
                  Ajouté le {new Date(doc.uploaded_at).toLocaleDateString('fr-FR')}
                </p>
                {doc.description && (
                  <p className="text-xs text-muted-foreground truncate">
                    {doc.description}
                  </p>
                )}
              </div>
            </div>
            <div className="flex space-x-1 flex-shrink-0">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => viewDocument(doc)}
                title="Voir le document"
              >
                <Eye className="h-4 w-4" />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  const url = doc.document_url.includes('public/employee-documents') 
                    ? doc.document_url 
                    : `/storage/employee-documents/${doc.document_url.split('/').pop()}`;
                  downloadDocument(url, doc.document_name);
                }}
                title="Télécharger"
              >
                <Download className="h-4 w-4" />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => onDelete(doc.id)}
                title="Supprimer"
                className="text-destructive hover:text-destructive"
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
};

export default DocumentList;