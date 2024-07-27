import pandas as pd
from dash import Dash, dcc, html, dash_table
from dash.dependencies import Input, Output
import plotly.express as px

# Function to read anomalies from the file
def read_anomalies(file_path):
    print(f"Reading anomalies from {file_path}...")
    df = pd.read_csv(file_path, sep=' ', names=[
        'timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
        'tos', 'ttl', 'id', 'offset', 'flags', 'length', 'flags2', 'seq',
        'ack', 'win', 'length2', 'details', 'anomaly'
    ])
    return df

# Read anomalies
anomalies_df = read_anomalies("/home/jared/oai-cn5g/flask_server/results/anomalies_detected.txt")

# Group by src_ip and anomaly to get the count
anomaly_counts = anomalies_df.groupby(['src_ip', 'anomaly']).size().reset_index(name='count')

# Create a Dash application
app = Dash(__name__)

# Create a figure for the anomalies detected by source IP
def create_anomaly_figure(df):
    fig = px.bar(df, x='src_ip', y='count', color='anomaly', title='Anomalies Detected by Source IP and Rule Set', labels={'count':'Number of Anomalies'})
    fig.update_layout(xaxis_title='Source IP', yaxis_title='Number of Anomalies')
    return fig

# Layout of the Dash application
app.layout = html.Div(children=[
    html.H1(children='Anomaly Detection Dashboard'),

    dcc.Graph(
        id='anomaly-graph',
        figure=create_anomaly_figure(anomaly_counts)
    ),

    html.H2(children='Anomaly Details'),
    dash_table.DataTable(
        id='anomaly-details-table',
        columns=[{"name": i, "id": i} for i in anomalies_df.columns],
        page_size=10,
        style_cell={'textAlign': 'left'},  # Align text to the left
        style_table={'width': '100%'},
        style_data_conditional=[{
            'if': {'column_id': c},
            'textAlign': 'left'
        } for c in anomalies_df.columns]
    )
])

# Callback to update the DataTable based on bar selection
@app.callback(
    Output('anomaly-details-table', 'data'),
    Input('anomaly-graph', 'clickData')
)
def update_table(clickData):
    if clickData is None:
        return []

    selected_data = clickData['points'][0]
    src_ip = selected_data['x']
    anomaly_index = selected_data['curveNumber']
    anomaly_type = anomaly_counts['anomaly'].unique()[anomaly_index]

    filtered_df = anomalies_df[
        (anomalies_df['src_ip'] == src_ip) &
        (anomalies_df['anomaly'] == anomaly_type)
    ]
    return filtered_df.to_dict('records')

# Run the Dash application
if __name__ == '__main__':
    app.run_server(debug=True, host='0.0.0.0', port=8050)
